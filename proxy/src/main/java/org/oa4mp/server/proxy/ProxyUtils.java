package org.oa4mp.server.proxy;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.server.OA2ATException;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import org.oa4mp.server.admin.oauth2.tools.OA2CLCCommands;
import org.oa4mp.server.admin.oauth2.tools.OA2CommandLineClient;
import org.oa4mp.server.api.storage.servlet.AbstractAuthorizationServlet;
import org.oa4mp.server.api.storage.servlet.AuthorizationServletConfig;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.RFC8628Constants2;
import org.oa4mp.server.loader.oauth2.servlet.RFC8628State;
import org.oa4mp.server.loader.oauth2.state.ExtendedParameters;
import org.oa4mp.server.loader.oauth2.storage.RFC8628Store;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.*;

import static java.net.URLEncoder.encode;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.oa4mp.server.api.storage.servlet.AbstractAuthorizationServlet.*;
import static org.oa4mp.server.proxy.OA2AuthorizationServer.scopesToString;

/**
 * Class with shared proxy utilities. The client uses this to send requests via the proxy.
 * The server hosting the proxy uses the RFC8628 servlets to process these.
 * <p>Created by Jeff Gaynor<br>
 * on 3/4/22 at  4:55 PM
 */
public class ProxyUtils {

    /**
     * For device flows, if requiring local consent is enabled, this is the parameter that is
     * sent. It is the redirect on the proxy side back to this site's consent machinery.
     */
    public static final String LOCAL_DF_CONSENT_XA = ExtendedParameters.OA4MP_NS + ":/proxy/df/consent_uri";

    protected static void doProxy(OA2SE oa2SE, RFC8628AuthorizationServer.PendingState pendingState) throws Throwable {
        RFC8628Store<? extends OA2ServiceTransaction> rfc8628Store = (RFC8628Store) oa2SE.getTransactionStore();
        OA2ServiceTransaction t = rfc8628Store.getByUserCode("");
        startProxyAuthCodeFlow(oa2SE, t, pendingState.getResponse());
    }

    protected static void doProxy(OA2SE oa2SE, AbstractAuthorizationServlet.AuthorizedState state) throws Throwable {
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
        startProxyAuthCodeFlow(oa2SE, t, state.getResponse());
    }

    /**
     * Starts the authorization code flow in the proxy. It redirects the user's browser. When done, the
     * callback the proxy uses is to the {@link ProxyCallbackServlet}'s ready endpoint.
     *
     * @param oa2SE
     * @param t
     * @param response
     * @throws Throwable
     */
    protected static void startProxyAuthCodeFlow(OA2SE oa2SE, OA2ServiceTransaction t, HttpServletResponse response) throws Throwable {

        OA2CLCCommands clcCommands = createCLC(oa2SE, t);
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(t.getOA2Client());
        debugger.trace(ProxyUtils.class, "doProxyRedirect, response committed? " + response.isCommitted());
        AbstractAuthorizationServlet.MyHttpServletResponseWrapper wrapper = new AbstractAuthorizationServlet.MyHttpServletResponseWrapper(response);
        // set the specific scopes.
        Collection<String> requestScopes = getRequestScopes(t, clcCommands);

        //InputLine inputLine = new InputLine("set_param", OA2CLCCommands.SHORT_REQ_PARAM_SWITCH, OA2Constants.SCOPE, scopesToString(clcCommands.getCe().getScopes()));
        InputLine inputLine = new InputLine("set_param", OA2CLCCommands.SHORT_REQ_PARAM_SWITCH, OA2Constants.SCOPE, scopesToString(requestScopes));
        clcCommands.set_param(inputLine);
        debugger.trace(ProxyUtils.class, "doProxyRedirect setting input:" + inputLine);
        Identifier identifier = BasicIdentifier.randomID();
        String id = Base64.getEncoder().encodeToString(identifier.toString().getBytes(UTF_8));
        t.setProxyId(identifier.toString());
        t.setAuthGrantValid(true);
        InputLine inputLine2 = new InputLine("set_param", OA2CLCCommands.SHORT_REQ_PARAM_SWITCH, OA2Constants.STATE, id);
        debugger.trace(ProxyUtils.class, "doProxyRedirect setting input:" + inputLine2);
        clcCommands.set_param(inputLine2);
        clcCommands.uri(new InputLine("uri")); // side effect is to set the uri
        DebugUtil.trace(ProxyUtils.class, "uri to proxy=" + clcCommands.getCurrentURI());
        URI uri = clcCommands.getCurrentURI();
        t.setProxyState(clcCommands.toJSON());
        // Here's where we need to poke at this.
        oa2SE.getTransactionStore().save(t); // save that proxy id!
        debugger.trace(ProxyUtils.class, "doProxyRedirect, wrapper committed? " + wrapper.isCommitted());
        String uriString = uri.toString();

        wrapper.sendRedirect(uriString);
    }

    /**
     * Starts device flow with proxy and populates the {@link RFC8628State} with the information
     * from the proxy. This returns the proxy's user code.
     *
     * @param oa2SE
     * @param t
     * @param rfc8628State
     * @return
     * @throws Exception
     */
    protected static String startProxyDeviceFlow(OA2SE oa2SE, OA2ServiceTransaction t, RFC8628State rfc8628State) throws Throwable {
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(t.getOA2Client());
        debugger.trace(ProxyUtils.class, "starting getProxyUserCode");
        OA2CLCCommands clcCommands = createCLC(oa2SE, t);
        Collection<String> requestScopes = getRequestScopes(t, clcCommands);

        InputLine inputLine = new InputLine("set_param", OA2CLCCommands.SHORT_REQ_PARAM_SWITCH, OA2Constants.SCOPE, scopesToString(requestScopes));
        debugger.trace(ProxyUtils.class, "getProxyUserCode input line=" + inputLine);
        clcCommands.set_param(inputLine);
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
         The look up at our end is in whatever canonical form we have set. The user may type in
         whatever they want as long as the letters are (up to case) the same, so a user code
         of "abc-def-g" might come back as "aBc DE+fg". We have to look this up on on our side
         so we always set the user code in the transaction (which is actually a unique key in
         the store) to the uppercase canonical form.

         Also, the proxy may have any policy it likes but displays the code it sent on the user consent page.
         We want to be sure that what the user gets from us is what they will see on the proxy's consent
         page (or they should, actually, refuse it, even though they may type in something equivalent.)
         */
        String userCodeKey = RFC8628Servlet.convertToCanonicalForm(rfc8628State.userCode, oa2SE.getRfc8628ServletConfig());
        userCodeKey = userCodeKey.toUpperCase();
        t.setUserCode(userCodeKey);
        debugger.trace(ProxyUtils.class, "getProxyUserCode setting user code = " + userCodeKey);
        oa2SE.getTransactionStore().save(t); // save that proxy id!
        return rfc8628State.userCode; // what the proxy sent.
    }


    /**
     * Takes the verification_uri_complete from the CLC (on the proxy site) and forwards the user's browser so
     * they can log in on the proxy server.
     *
     * @param oa2SE
     * @param t
     */
    protected static void userCodeToProxyRedirect(OA2SE oa2SE, OA2ServiceTransaction t, RFC8628AuthorizationServer.PendingState pendingState) throws Throwable {
        HttpServletResponse response = pendingState.getResponse();
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(t.getOA2Client());

        // Now we have determined that this is a pending transaction
        debugger.trace(ProxyUtils.class, "userCodeToProxyRedirect loading proxy client");
        debugger.trace(ProxyUtils.class, "userCodeToProxyRedirect response committed? " + response.isCommitted());
        AbstractAuthorizationServlet.MyHttpServletResponseWrapper wrapper = new AbstractAuthorizationServlet.MyHttpServletResponseWrapper(response);

        OA2CLCCommands clcCommands = getCLC(oa2SE, t);
        JSONObject dfResponse = clcCommands.getDfResponse();
        String rawCB = dfResponse.getString(RFC8628Constants2.VERIFICATION_URI_COMPLETE);
        if(oa2SE.getAuthorizationServletConfig().isLocalDFConsent()){
            String callback = oa2SE.getServiceAddress() + "/device?action=" + AUTHORIZATION_ACTION_DF_CONSENT_VALUE + "&user_code=" + t.getUserCode();
            rawCB = rawCB + "&" + encode(LOCAL_DF_CONSENT_XA, UTF_8) + "=" + encode(callback, UTF_8);
        }
        debugger.trace(ProxyUtils.class, "userCodeToProxyRedirect got DF response, raw callback =" + rawCB);
        debugger.trace(ProxyUtils.class, "userCodeToProxyRedirect wrapper committed? " + wrapper.isCommitted());
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
    protected static OA2CLCCommands getCLC(OA2SE oa2SE, OA2ServiceTransaction t) throws Throwable {
        //OA2CLCCommands clcCommands = new OA2CLCCommands(oa2SE.getMyLogger(), new OA2CommandLineClient(oa2SE.getMyLogger()));
        CLIDriver driver = new CLIDriver();
        OA2CLCCommands clcCommands = new OA2CLCCommands(driver, new OA2CommandLineClient(driver));
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
    protected static OA2CLCCommands createCLC(OA2SE oa2SE, OA2ServiceTransaction t) throws Throwable {
        AuthorizationServletConfig asc = oa2SE.getAuthorizationServletConfig();
        if(t.getClient().isDebugOn()){
            oa2SE.getMyLogger().debug("authz servlet config = " + asc);
        }

        // next line is where the CLC is first created in the flow, so can't call getCLC
        CLIDriver driver = new CLIDriver();
        OA2CLCCommands clcCommands = new OA2CLCCommands(true, driver, new OA2CommandLineClient(driver));
        //OA2CLCCommands clcCommands = new OA2CLCCommands(true, oa2SE.getMyLogger(), new OA2CommandLineClient(oa2SE.getMyLogger()));
        clcCommands.setUseClipboard(false); // Don't put stuff in the clipboard.
        if (t.getOA2Client().isDebugOn()) {
            // Turn it all on if the client is in debug mode.
            driver.setOutputOn(true);
            driver.setVerbose(true);
        }
        clcCommands.load(new InputLine("dummy ", asc.getCfgName(), asc.getCfgFile()));
        //   This was to fix CIL-1419 but the actual issue was not that the client should dictate the proxy's
        //   scopes, but that the client and proxy scopes need to be independent (done in CIL-1212) and configured
        //   correctly.
        //   CIL-1419 make sure requests match allowed scopes
        //   clcCommands.getCe().setScopes(t.getScopes());
        return clcCommands;
    }

    /**
     * Gets the access token from the Proxy. This then finishes setting up the claims locally.
     * @param oa2SE
     * @param t
     * @throws Throwable
     */
    protected static void getProxyAccessToken(OA2SE oa2SE, OA2ServiceTransaction t) throws Throwable {
        if(t.isProxyAccessTokenComplete()) return; // already done
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(t.getOA2Client());

        // Now we have determined that this is a pending transaction
        debugger.trace(ProxyUtils.class, "doRFC8628AT, loading proxy client");

        OA2CLCCommands clcCommands = getCLC(oa2SE, t);
        Collection<String> requestScopes = getRequestScopes(t, clcCommands);

        //InputLine inputLine = new InputLine("set_param", OA2CLCCommands.SHORT_REQ_PARAM_SWITCH, OA2Constants.SCOPE, scopesToString(t));

        InputLine inputLine = new InputLine("set_param", OA2CLCCommands.SHORT_REQ_PARAM_SWITCH, OA2Constants.SCOPE, scopesToString(requestScopes));
        debugger.trace(ProxyUtils.class, "doRFC8628AT input line: " + inputLine);
        clcCommands.set_param(inputLine);
        try {
            clcCommands.access(new InputLine("access "));
        } catch (Throwable throwable) {
            debugger.trace(ProxyUtils.class, "error contacting proxy", throwable);
            if (throwable instanceof ServiceClientHTTPException) {
                throw toOA2ATException((ServiceClientHTTPException) throwable, t);
            }
            throw throwable;
        }
        if (clcCommands.hadException()) {
            debugger.trace(ProxyUtils.class, "doRFC8628AT got an exception in CLC");
            Throwable throwable = clcCommands.getLastException(); // This is a ServiceClientHTTPException so just pass it along

            if (throwable instanceof ServiceClientHTTPException) {
                throw toOA2ATException((ServiceClientHTTPException) throwable, t);
            }

            debugger.trace(ProxyUtils.class, "doRFC8628AT error contacting proxy", throwable);
            throw throwable;
        }
        debugger.trace(ProxyUtils.class, "doRFC8628AT finished getting access token.");
        // So this worked. Rock on!
        try {
            t.setProxyState(clcCommands.toJSON());
            debugger.trace(ProxyUtils.class, "doRFC8628AT saving proxy state.");
            setClaimsFromProxy(t, clcCommands.getIdToken().getPayload(), debugger);
            t.setProxyAccessTokenComplete(true);
            oa2SE.getTransactionStore().save(t);
        } catch (Throwable throwable) {
            if (debugger.isEnabled()) {
                throwable.printStackTrace();
            }
            throw throwable;
        }
        debugger.trace(ProxyUtils.class, "doRFC8628AT done.");
    }

    /**
     * Handles various types of exceptions, transforming them  to an {@link OA2ATException}.
     * @param serviceClientHTTPException
     * @param t
     * @return
     */
    protected static OA2ATException toOA2ATException(ServiceClientHTTPException serviceClientHTTPException, OA2ServiceTransaction t) {
        JSONObject content = JSONObject.fromObject(serviceClientHTTPException.getContent());
        throw new OA2ATException(content.getString(OA2Constants.ERROR),
                content.getString(OA2Constants.ERROR_DESCRIPTION),
                serviceClientHTTPException.getStatus(), t.getRequestState(), t.getClient());

    }

    /**
     * Takes the claims returned fromthe proxy and adds them to the transaction
     * @param t
     * @param proxyClaims
     * @param debugger
     */
    protected static void setClaimsFromProxy(OA2ServiceTransaction t, JSONObject proxyClaims, MetaDebugUtil debugger) {
        debugger.trace(ProxyUtils.class, "setClaimsFromProxy starting");
        JSONObject claims = t.getUserMetaData();
        claims.put(OA2Claims.SUBJECT, proxyClaims.get(OA2Claims.SUBJECT));  // always
        t.setUsername(proxyClaims.getString(OA2Claims.SUBJECT)); // This is where this is set.
        Collection<String> proxyClaimKeys = t.getOA2Client().getProxyClaimsList();
        debugger.trace(ProxyUtils.class, "setClaimsFromProxy populating proxy claims. list=" + proxyClaimKeys);
        if (proxyClaimKeys.isEmpty()) {
            // do nothing -- default is just to return the subject
        } else {
            if (proxyClaimKeys.contains("*")) {
                proxyClaimKeys = new ArrayList<>();
                proxyClaimKeys.addAll(proxyClaims.keySet());
                proxyClaimKeys.remove(OA2Claims.AUDIENCE);
                proxyClaimKeys.remove(OA2Claims.ISSUER);
                proxyClaimKeys.remove(OA2Claims.ISSUED_AT);
                proxyClaimKeys.remove(OA2Claims.EXPIRATION);
                proxyClaimKeys.remove(OA2Constants.ID_TOKEN_IDENTIFIER);
            }

            for (String claim : proxyClaimKeys) {
                if (proxyClaims.containsKey(claim)) {
                    Object x = proxyClaims.get(claim);
                    debugger.trace(ProxyUtils.class, "setClaimsFromProxy adding claim \"" + claim + "\" " + "with value " + x);
                    claims.put(claim, x);
                }
            }
        }
        debugger.trace(ProxyUtils.class, "created claims, returning " + claims.toString(2));
        t.setUserMetaData(claims); // Get might have created a new one, so be sure it gets stashed right.
    }

    /**
     * Attempt to do a refresh of the claims from the proxy server. This is not used yet since there are a
     * lot of policy type decisions to make. For instance, what if the lifetimes of tokens on the proxy
     * are much shorter than on the server? Then there has to be some way to communicate that no updates
     * to the claims are possible.
     *
     * @param oa2SE
     * @param t
     * @throws Exception
     */
    protected static void doProxyClaimsRefresh(OA2SE oa2SE, OA2ServiceTransaction t) throws Throwable {
        OA2CLCCommands clcCommands = getCLC(oa2SE, t);
        try {
           //clcCommands.refresh(new InputLine("user_info "));
           clcCommands.refresh();
        }catch(Throwable throwable){
            setClaimsFromProxy(t, clcCommands.getIdToken().getPayload(), OA4MPServlet.createDebugger(t.getOA2Client()));
        }
        t.setProxyState(clcCommands.toJSON());
        oa2SE.getTransactionStore().save(t);

    }

    /**
     * This will take the various bits and determine the actual scopes that should be in the request to the proxy.
     * <h3>Logic</h3>
     * <ul>
     *     <li>forward scopes to proxy: <b>true</b> <br/>
     *          ⇒ forward everything allowed</li>
     *     <li>forward scopes to proxy: <b>false</b></li>
     *     <ul>
     *         <li>{@link OA2Client#getProxyRequestScopes()} is trivial<br/>
     *                 ⇒ forward full set of configured scopes for the proxy</li>
     *            <li>else<br/>
     *                 ⇒ forward intersection of this list with the configured scopes for the proxy</li>
     *            <li>If the proxy requests scopes contains the reserved scope of {@link #NO_PROXY_SCOPES},
     *            then request no scopes at all from the proxy server.</li>
     *     </ul>
     * </ul>
     * When we say above to forward everything allowed, we mean that the policies for scopes are applied
     * to the request as per usual (e.g. a public client with strict scopes on cannot even
     * make a request with extra scopes). On top of this, even if the client requests forwarding, the proxy itself
     * may restrict scopes and is free to reject them.
     *
     * @param t
     * @param clcCommands
     * @return
     */
    // CIL-1584
    protected static Collection<String> getRequestScopes(OA2ServiceTransaction t, OA2CLCCommands clcCommands) {
        OA2Client oa2Client = t.getOA2Client();
        if (oa2Client.isForwardScopesToProxy()) {
            // Remember that server policies have been applied to this list of scopes already.
            return t.getScopes();
        }
        Set<String> requestScopes = new HashSet<>();
        requestScopes.addAll(clcCommands.getCe().getScopes());
        if (oa2Client.hasRequestScopes()) {

            if (oa2Client.getProxyRequestScopes().contains("*")) {
                // Asks for all scopes.
                return clcCommands.getCe().getScopes();
            }
            requestScopes.retainAll(oa2Client.getProxyRequestScopes());
        }
        return requestScopes;
    }

    public static final String NO_PROXY_SCOPES = "--";

    public static X509Certificate[] getCerts(OA2SE oa2SE, OA2ServiceTransaction t) throws Throwable {
        OA2CLCCommands clc = getCLC(oa2SE, t);
        return clc.getX509Certificates();
    }
}
