package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.request.PARequest;
import edu.uiuc.ncsa.security.delegation.server.request.PAResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/13 at  3:36 PM
 */
public abstract class AbstractCertServlet extends MyProxyDelegationServlet {
    protected PAIssuer getPAI() throws IOException {
        return getServiceEnvironment().getPaIssuer();
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        doDelegation(httpServletRequest, httpServletResponse);

    }


    protected void doDelegation(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        info("6.a. Starting to process cert request");
        PARequest paRequest = new PARequest(httpServletRequest, getClient(httpServletRequest));
        String cc = "client = " + paRequest.getClient().getIdentifier();
        paRequest.setAccessToken(getServiceEnvironment().getTokenForge().getAccessToken(httpServletRequest));

        PAResponse paResponse = (PAResponse) getPAI().process(paRequest);
        AccessToken accessToken = paResponse.getAccessToken();
        debug("6.a. " + cc);

        ServiceTransaction t = verifyAndGet(paResponse);
        info("6.a. Processing request for transaction " + t.getIdentifier());
        t.setAccessTokenValid(false);
        preprocess(new TransactionState(httpServletRequest, httpServletResponse, paResponse.getParameters(), t));

        debug("6.a. protected asset:" + (t.getProtectedAsset() == null ? "(null)" : "ok") + ", " + cc);
        HashMap<String, String> username = new HashMap<String, String>();
        username.put("username", t.getUsername());
        username.putAll(paResponse.getParameters());
        paResponse.setAdditionalInformation(username);
        paResponse.setProtectedAsset(t.getProtectedAsset());
        debug("6.a. Added username \"" + t.getUsername() + "\" & cert for request from " + cc);
        getTransactionStore().save(t);

        info("6.b. Done with cert request " + cc);
        paResponse.write(httpServletResponse);
        info("6.b. Completed transaction " + t.getIdentifierString() + ", " + cc);
        postprocess(new TransactionState(httpServletRequest, httpServletResponse, paResponse.getParameters(), t));
    }

}
