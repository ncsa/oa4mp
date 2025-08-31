package org.oa4mp.server.proxy;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringEscapeUtils;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.jwt.HandlerRunner;
import org.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.server.admin.oauth2.tools.OA2CLCCommands;
import org.oa4mp.server.admin.oauth2.tools.OA2CommandLineClient;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.OA2ClientUtils;
import org.oa4mp.server.loader.oauth2.servlet.OA2ServletUtils;
import org.oa4mp.server.loader.oauth2.state.ScriptRuntimeEngineFactory;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;
import static org.oa4mp.server.api.ServiceConstantKeys.TOKEN_KEY;
import static org.oa4mp.server.proxy.ProxyUtils.setClaimsFromProxy;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/3/22 at  4:33 PM
 */
public class ProxyCallbackServlet extends OA2AuthenticationServer {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    /**
     * Processes the callback <i>from the proxy</i>. This will take the proxy's callback and transform it
     * into the correct transaction at our end, then get the access token from the proxy.
     * <br/>
     * The access token also includes the user's meta data (such as subject) and the is used to
     * populate the username in the server. When this is done, the server is ready to do its callback.
     *
     * @param request
     * @param response
     * @throws Throwable
     */
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        Map<String, String[]> parameters = request.getParameterMap();

        if (!parameters.containsKey(OA2Constants.STATE)) {
            throw new IllegalStateException("No state");
        }
        String[] states = parameters.get(OA2Constants.STATE);
        if (states.length == 0) {
            throw new IllegalStateException("No state");
        }
        // only use the first state parameter.
        Identifier proxyID = BasicIdentifier.newID(new String(Base64.getDecoder().decode(states[0])));
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();
        OA2ServiceTransaction t = (OA2ServiceTransaction) oa2SE.getTransactionStore().getByProxyID(proxyID);
        if (t == null) {
            throw new IllegalStateException("No transaction for proxy ID \"" + proxyID + "\"");
        }
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(t.getOA2Client());
        debugger.trace(this, "request uri= " + request.getRequestURI());
        // Now we have determined that this is a pending transaction
        debugger.trace(this, "loading proxy client");
        //OA2CLCCommands clcCommands = new OA2CLCCommands(getMyLogger(), new OA2CommandLineClient(getMyLogger()));
        CLIDriver driver = new CLIDriver();
        OA2CLCCommands clcCommands = new OA2CLCCommands(driver, new OA2CommandLineClient(driver));
        JSONObject proxyState = t.getProxyState();
        if (proxyState.isEmpty()) {
            throw new TransactionNotFoundException("No pending proxy transaction was found");
        }
        clcCommands.fromJSON(proxyState);
        // go get the claims All we can do is half-assed reconstruct the URI and forgoe checking it.
        clcCommands.grant(new InputLine("grant  " + OA2CLCCommands.NO_VERIFY_GRANT_FLAG + " " + request.getRequestURL() + "?" + request.getQueryString()));
        debugger.trace(this, "getting claims from proxy");
        clcCommands.access(new InputLine("access")); // This gets the
        // At the least, do this
        JSONObject proxyClaims = clcCommands.getIdToken().getPayload();
        t.setProxyState(clcCommands.toJSON());

        setClaimsFromProxy(t, proxyClaims, debugger);
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, t.getOA2Client());
        // Do any scripting
        HandlerRunner handlerRunner = new HandlerRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, resolvedClient.getConfig()));
        OA2ClientUtils.setupHandlers(handlerRunner, oa2SE, t, resolvedClient, request);
        XMLMap backup = GenericStoreUtils.toXML(getTransactionStore(), t);
        Date now  = new Date();
        t.setAuthTime(now);
        t.getClient().setLastAccessed(now);
        try {
            handlerRunner.doAuthClaims();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2SE, throwable, createDebugger(t.getClient()), t, backup);
        }
        // At this point, the user has logged in, the transaction state should be correct, so we need to
        // create the correct callback and return it.
        Map<String, String> cbParams = new HashMap<>();
        cbParams.put(OA2Constants.STATE, t.getRequestState()); // Make sure that the original state that was sent is returned to the client callback
        String cb = createCallback(t, cbParams);
        oa2SE.getTransactionStore().save(t);
     //   response.sendRedirect(cb);
        if(oa2SE.getAuthorizationServletConfig().isLocalDFConsent()) {
            setClientConsentAttributes(request, t);
            JSPUtil.fwd(request, response, "/proxy-consent.jsp");
        }else {
            response.sendRedirect(cb);
        }
    }
    protected void setClientConsentAttributes(HttpServletRequest request, OA2ServiceTransaction t) {
        request.setAttribute(AUTHORIZATION_ACTION_KEY, AUTHORIZATION_ACTION_KEY);
        request.setAttribute("actionOk", AUTHORIZATION_ACTION_OK_VALUE);
        request.setAttribute("authorizationGrant", t.getIdentifierString());
        request.setAttribute("tokenKey", CONST(TOKEN_KEY));
        // OAuth 2.0 specific values that must be preserved.
        request.setAttribute("stateKey", "state");
 //       request.setAttribute("authorizationState", t.getRequestState());

        request.setAttribute("clientHome", escapeHtml(t.getClient().getHomeUri()));
        request.setAttribute("clientName", escapeHtml(t.getClient().getName()));
        request.setAttribute("clientScopes", StringEscapeUtils.escapeHtml(scopesToString(t)));

        request.setAttribute("actionToTake", request.getContextPath() + "/authorize");
    }

}
