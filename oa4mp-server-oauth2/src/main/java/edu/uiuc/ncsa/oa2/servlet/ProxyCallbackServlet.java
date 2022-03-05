package edu.uiuc.ncsa.oa2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTRunner;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.STATE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/3/22 at  4:33 PM
 */
public class ProxyCallbackServlet extends OA2AuthorizationServer {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        //https://localhost:9443/client/not-ready?
        // code=NB2HI4DTHIXS6ZDFOYXGG2LMN5TW63RON5ZGOL3PMF2XI2BSF4YTANTGGBQWMNBRMU3WEOLFMQ4TQNTGGE3WGMZYGYYTOZRZMFSGKP3UPFYGKPLBOV2GQ6SHOJQW45BGORZT2MJWGQ3DGNBWG42DGNRUGATHMZLSONUW63R5OYZC4MBGNRUWMZLUNFWWKPJZGAYDAMBQ&
        // state=dXJuOmlkOjUyZjBjMGU3LWE4YzYtNDIxNy05Y2YxLWJjOTJmNzQwNGQ2NQ%3D%3D
        Map<String, String[]> parameters = request.getParameterMap();
        System.out.println(getClass().getSimpleName() + ": request uri= " + request.getRequestURI());

        if (!parameters.containsKey(STATE)) {
            throw new IllegalStateException("No state");
        }
        String[] states = parameters.get(STATE);
        if (states.length == 0) {
            throw new IllegalStateException("No state");
        }
        // only use the first state parameter.
        Identifier proxyID = BasicIdentifier.newID(new String(Base64.getDecoder().decode(states[0])));
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        OA2ServiceTransaction t = (OA2ServiceTransaction) oa2SE.getTransactionStore().getByProxyID(proxyID);
        if (t == null) {
            throw new IllegalStateException("No transaction for proxy ID \"" + proxyID + "\"");
        }
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(t.getOA2Client());

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
        JSONObject claims = t.getUserMetaData();
        claims.put(OA2Claims.SUBJECT, proxyClaims.get(OA2Claims.SUBJECT));
        t.setProxyState(clcCommands.toJSON());

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
        t.setUserMetaData(claims);
        // oa2SE.getTransactionStore().save(t);
        // Do any scripting
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, t.getOA2Client().getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, t, request);

        jwtRunner.doAuthClaims();

        oa2SE.getTransactionStore().save(t);
        // At this point, the user has logged in, the transaction state should be correct, so we need to
        // create the correct callback and return it.
        Map<String, String> cbParams = new HashMap<>();
        cbParams.put(STATE, t.getRequestState()); // Make sure that the original state that was sent is returned to the client callback
        String cb = createCallback(t, cbParams);
        response.sendRedirect(cb);

        // createRedirect(request, response, t);
        //       super.doIt(request, response);

    }

}
