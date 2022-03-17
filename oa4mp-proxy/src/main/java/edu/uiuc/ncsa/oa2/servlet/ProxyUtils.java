package edu.uiuc.ncsa.oa2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628Constants2;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RFC8628Store;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;

import static edu.uiuc.ncsa.oa2.servlet.OA2AuthorizationServer.scopesToString;

/**
 * Class with shared proxy utilities
 * <p>Created by Jeff Gaynor<br>
 * on 3/4/22 at  4:55 PM
 */
public class ProxyUtils {

    protected static void doProxy(OA2SE oa2SE, RFC8628AuthorizationServer.PendingState pendingState) throws Throwable {
        RFC8628Store<? extends OA2ServiceTransaction> rfc8628Store = (RFC8628Store) oa2SE.getTransactionStore();
        OA2ServiceTransaction t = rfc8628Store.getByUserCode("");
        doProxyRedirect(oa2SE, t, pendingState.getResponse());
    }

    protected static void doProxy(OA2SE oa2SE, AbstractAuthorizationServlet.AuthorizedState state) throws Throwable {
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
        doProxyRedirect(oa2SE, t, state.getResponse());
    }

    /**
     * In the Authorization servlet, this creates the redirect to the proxy and redirects the user's browser.
     *
     * @param oa2SE
     * @param t
     * @param response
     * @throws Throwable
     */
    protected static void doProxyRedirect(OA2SE oa2SE, OA2ServiceTransaction t, HttpServletResponse response) throws Throwable {
        OA2CLCCommands clcCommands = createCLC(oa2SE, t);

        AbstractAuthorizationServlet.MyHttpServletResponseWrapper wrapper = new AbstractAuthorizationServlet.MyHttpServletResponseWrapper(response);
        // set the specific scopes.
        clcCommands.set_param(new InputLine("set_param -a scope \"" + scopesToString(t) + "\""));
        Identifier identifier = BasicIdentifier.randomID();
        String id = Base64.getEncoder().encodeToString(identifier.toString().getBytes(StandardCharsets.UTF_8));
        t.setProxyId(identifier.toString());
        t.setAuthGrantValid(true);
        clcCommands.set_param(new InputLine("set_param -a state " + id));
        clcCommands.uri(new InputLine("uri")); // side effect is to set the uri
        DebugUtil.trace(ProxyUtils.class, "uri to proxy=" + clcCommands.getCurrentURI());
        URI uri = clcCommands.getCurrentURI();
        t.setProxyState(clcCommands.toJSON());
        // Here's where we need to poke at this.
        oa2SE.getTransactionStore().save(t); // save that proxy id!
        wrapper.sendRedirect(uri.toString());
    }

    /**
     * Sets up device flow with proxy and populates the {@link RFC8628State} with the information
     * from the proxy. This returns the proxy's user code.
     *
     * @param oa2SE
     * @param t
     * @param rfc8628State
     * @return
     * @throws Exception
     */
    protected static String getProxyUserCode(OA2SE oa2SE, OA2ServiceTransaction t, RFC8628State rfc8628State) throws Exception {
        OA2CLCCommands clcCommands = createCLC(oa2SE, t);
        clcCommands.set_param(new InputLine("set_param " + OA2CLCCommands.SHORT_REQ_PARAM_SWITCH + " " + OA2Constants.SCOPE + " \"" + scopesToString(t) + "\""));
        clcCommands.df(new InputLine("df"));
        // Caveat. The device code is the auth grant from the proxy. We have to manage the one from
        // the proxy (to talk to that service) and the one from this server.
        // Do not set the device code here, let the CLC manage the one from the proxy.
        rfc8628State.userCode = clcCommands.getUserCode();
        rfc8628State.lifetime = clcCommands.getDfExpiresIn() * 1000;
        rfc8628State.interval = clcCommands.getDfInterval() * 1000;
        rfc8628State.issuedAt = System.currentTimeMillis();
        t.setProxyState(clcCommands.toJSON());
        /*
         As long as every device flow request uses a single proxy, the
         proxy should ensure there are not collisions. IF we ever decide to allow multiple
         proxies, then this is the place to check and reget until there is no collision.
         This is the point at which would check for user code collisions in the very slight chance
         that there is one.
         */
        /*
         The look up at our end is in whatever canonical form we have set. The user may type iin
         whatever they want as long as the letters are (up to case) the same, so a user code
         of "abc-def-g" might come back as "aBc DE+fg". We have to look this up on on ourside
         so we always set the user code in the transaction (which is actually a unique key in
         the store) to the uppercase canonical form.

         Also, the proxy may have any policy it likes but displays the code it sent on the user consent page.
         We want to be sure that what the user gets from us is what they will see on the proxy's consent
         page (or they should, actually, refuse it, even though they may type in something equivalent.)
         */
        String userCodeKey = RFC8628Servlet.convertToCanonicalForm(rfc8628State.userCode, oa2SE.getRfc8628ServletConfig());
        userCodeKey = userCodeKey.toUpperCase();
        t.setUserCode(userCodeKey);
        oa2SE.getTransactionStore().save(t); // save that proxy id!
        return rfc8628State.userCode; // what the proxy sent.
    }


    /**
     * Takes the user code in the service transaction (which has been found) and does
     * the redirect to the proxy for login. For RFC8628
     *
     * @param oa2SE
     * @param t
     * @return
     */
    protected static void userCodeToProxyRedirect(OA2SE oa2SE, OA2ServiceTransaction t, RFC8628AuthorizationServer.PendingState pendingState) throws Exception {
        HttpServletResponse response = pendingState.getResponse();
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(t.getOA2Client());

        // Now we have determined that this is a pending transaction
        debugger.trace(ProxyUtils.class, "loading proxy client");

        AbstractAuthorizationServlet.MyHttpServletResponseWrapper wrapper = new AbstractAuthorizationServlet.MyHttpServletResponseWrapper(response);

        OA2CLCCommands clcCommands = getCLC(oa2SE, t);
        JSONObject dfResponse = clcCommands.getDfResponse();
        String rawCB = dfResponse.getString(RFC8628Constants2.VERIFICATION_URI_COMPLETE);
        wrapper.sendRedirect(rawCB);

    }

    /**
     * Get the fully functional CLC (Command Line Client) associated with this transaction.
     * Note that if you update the client, you must save the state
     *
     * @param oa2SE
     * @param t
     * @return
     * @throws Exception
     */
    protected static OA2CLCCommands getCLC(OA2SE oa2SE, OA2ServiceTransaction t) throws Exception {
        OA2CLCCommands clcCommands = new OA2CLCCommands(oa2SE.getMyLogger(), new OA2CommandLineClient(oa2SE.getMyLogger()));
        JSONObject proxyState = t.getProxyState();
        if (proxyState.isEmpty()) {
            throw new TransactionNotFoundException("No pending proxy transaction was found");
        }
        clcCommands.fromJSON(proxyState);
        return clcCommands;
    }

    /**
     * Create a completely new CLC and load the configuration into it.
     *
     * @param oa2SE
     * @param t
     * @return
     * @throws Exception
     */
    protected static OA2CLCCommands createCLC(OA2SE oa2SE, OA2ServiceTransaction t) throws Exception {
        AuthorizationServletConfig asc = oa2SE.getAuthorizationServletConfig();
        // next line is where the CLC is first created in the flow, so can't call getCLC
        OA2CLCCommands clcCommands = new OA2CLCCommands(true, oa2SE.getMyLogger(), new OA2CommandLineClient(oa2SE.getMyLogger()));
        clcCommands.load(new InputLine("dummy " + asc.getCfgName() + "  " + asc.getCfgFile()));
        return clcCommands;
    }

    protected static void doRFC8628AT(OA2SE oa2SE, OA2ServiceTransaction t) throws Throwable {
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(t.getOA2Client());

        // Now we have determined that this is a pending transaction
        debugger.trace(ProxyUtils.class, "loading proxy client");

        OA2CLCCommands clcCommands = getCLC(oa2SE, t);
        clcCommands.set_param(new InputLine("set_param " + OA2CLCCommands.SHORT_REQ_PARAM_SWITCH + " " + OA2Constants.SCOPE + " \"" + scopesToString(t) + "\""));
        clcCommands.access(new InputLine("access "));
        if (clcCommands.hadException()) {
            Throwable throwable = clcCommands.getLastException();
            if (throwable instanceof ServiceClientHTTPException) {
                ServiceClientHTTPException serviceClientHTTPException = (ServiceClientHTTPException) throwable;
                JSONObject content = JSONObject.fromObject(serviceClientHTTPException.getContent());
                throw new OA2ATException(content.getString("error"),
                        content.getString("description"),
                        serviceClientHTTPException.getStatus(), t.getRequestState());
            }
            debugger.trace(ProxyUtils.class, "error contacting proxy", throwable);
            throw throwable;
        }
        // So this worked. Rock on!
        t.setProxyState(clcCommands.toJSON());
        setClaimsFromProxy(t, clcCommands.getClaims());

        oa2SE.getTransactionStore().save(t);
    }

    protected static void setClaimsFromProxy(OA2ServiceTransaction t, JSONObject proxyClaims) {
        JSONObject claims = t.getUserMetaData();
        claims.put(OA2Claims.SUBJECT, proxyClaims.get(OA2Claims.SUBJECT));  // always
        t.setUsername(proxyClaims.getString(OA2Claims.SUBJECT)); // This is where this is set.
        Collection<String> proxyClaimKeys = t.getOA2Client().getProxyClaimsList();
        if (proxyClaimKeys.isEmpty()) {
            // do nothing -- default is just to return the subject
        } else {
            if (proxyClaimKeys.contains("*")) {
                proxyClaimKeys = new ArrayList<>();
                proxyClaimKeys.addAll(proxyClaims.keySet());
                // do all of them.
            }
            // This is supposed to be a list
            for (String claim : proxyClaimKeys) {
                if (proxyClaims.containsKey(claim)) {
                    claims.put(claim, proxyClaims.get(claim));
                }
            }
        }
        t.setUserMetaData(claims); // Get might have created a new one, so be sure it gets stashed right.
    }

    /**
     * Attempt to do a refresh of the claims from the proxy server.
     *
     * @param oa2SE
     * @param t
     * @throws Exception
     */
    protected static void doProxyClaimsRefresh(OA2SE oa2SE, OA2ServiceTransaction t) throws Exception {
        OA2CLCCommands clcCommands = getCLC(oa2SE, t);
        clcCommands.refresh(new InputLine("user_info "));
        if (!clcCommands.hadException()) {
            setClaimsFromProxy(t, clcCommands.getClaims());
        }
        t.setProxyState(clcCommands.toJSON());
        oa2SE.getTransactionStore().save(t);

    }
}
