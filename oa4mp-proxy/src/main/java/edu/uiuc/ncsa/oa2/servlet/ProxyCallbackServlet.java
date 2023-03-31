package edu.uiuc.ncsa.oa2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ServletUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.JWTRunner;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.oa2.servlet.ProxyUtils.setClaimsFromProxy;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/3/22 at  4:33 PM
 */
public class ProxyCallbackServlet extends OA2AuthorizationServer {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    /**
     * Processes the callback <i>from the proxy</i>. This will take the proxy's callback and transform it
     * into the correct transactioin at our end, then get the access token from the proxy.
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
        //https://localhost:9443/client/not-ready?
        // code=NB2HI4DTHIXS6ZDFOYXGG2LMN5TW63RON5ZGOL3PMF2XI2BSF4YTANTGGBQWMNBRMU3WEOLFMQ4TQNTGGE3WGMZYGYYTOZRZMFSGKP3UPFYGKPLBOV2GQ6SHOJQW45BGORZT2MJWGQ3DGNBWG42DGNRUGATHMZLSONUW63R5OYZC4MBGNRUWMZLUNFWWKPJZGAYDAMBQ&
        // state=dXJuOmlkOjUyZjBjMGU3LWE4YzYtNDIxNy05Y2YxLWJjOTJmNzQwNGQ2NQ%3D%3D

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
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        OA2ServiceTransaction t = (OA2ServiceTransaction) oa2SE.getTransactionStore().getByProxyID(proxyID);
        if (t == null) {
            throw new IllegalStateException("No transaction for proxy ID \"" + proxyID + "\"");
        }
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(t.getOA2Client());
        debugger.trace(this, "request uri= " + request.getRequestURI());

        // Now we have determined that this is a pending transaction
        debugger.trace(this, "loading proxy client");
        OA2CLCCommands clcCommands = new OA2CLCCommands(getMyLogger(), new OA2CommandLineClient(getMyLogger()));
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
        JSONObject proxyClaims = clcCommands.getClaims();
        t.setProxyState(clcCommands.toJSON());

        setClaimsFromProxy(t, proxyClaims, debugger);
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, t.getOA2Client());
        // Do any scripting
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, resolvedClient.getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, t, resolvedClient, request);
        XMLMap backup = GenericStoreUtils.toXML(getTransactionStore(), t);
        /*
        CIL-1278 -- support goes here. These are scripts run by the server to
                    emulate CILogons getUser and setTransaction calls. This allows OA4MP to have
                    user support without explicitly having to store/manage users.
                    Code below is boilerplate to be used as a reference.
        if (!client.isSkipServerScripts() && oa2SE.getQDLEnvironment().hasServerScripts()) {
            ServerQDLScriptHandlerConfig qdlScriptHandlerConfig = new ServerQDLScriptHandlerConfig(oa2SE, transaction, atTX, req);
            ServerQDLScriptHandler qdlScriptHandler = new ServerQDLScriptHandler(qdlScriptHandlerConfig);
            jwtRunner.addHandler(qdlScriptHandler);
        }        }
         */
        try {
            jwtRunner.doAuthClaims();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2SE, throwable, createDebugger(t.getClient()), t, backup);
        }
        oa2SE.getTransactionStore().save(t);
        // At this point, the user has logged in, the transaction state should be correct, so we need to
        // create the correct callback and return it.
        Map<String, String> cbParams = new HashMap<>();
        cbParams.put(OA2Constants.STATE, t.getRequestState()); // Make sure that the original state that was sent is returned to the client callback
        String cb = createCallback(t, cbParams);
        response.sendRedirect(cb);
    }


}
