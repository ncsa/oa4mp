package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.security.delegation.server.request.ATResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.Verifier;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/13 at  1:37 PM
 */
public abstract class AbstractAccessTokenServlet extends MyProxyDelegationServlet {
    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        doDelegation(httpServletRequest, httpServletResponse);
    }

    /**
     * Note that this method does <b>not</b> write the response (using the issuer response). You must
     * do that in your implementation after you have finished all processing. If we were to do that here,
     * the response would be written prematurely.
     * @param httpServletRequest
     * @param httpServletResponse
     * @return
     * @throws Throwable
     * @throws ServletException
     */
    protected IssuerTransactionState doDelegation(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable, ServletException {
        printAllParameters(httpServletRequest);
        info("5.a. Starting access token exchange");
        Verifier v = getServiceEnvironment().getTokenForge().getVerifier(httpServletRequest);
        AuthorizationGrant ag = getServiceEnvironment().getTokenForge().getAuthorizationGrant(httpServletRequest);

        ATRequest atRequest = new ATRequest(httpServletRequest, getClient(httpServletRequest));

        atRequest.setVerifier(v);
        atRequest.setAuthorizationGrant(ag);
        atRequest.setExpiresIn(DateUtils.MAX_TIMEOUT); // FIXME!! make this configurable??
        ATResponse atResp = (ATResponse) getATI().process(atRequest);

        ServiceTransaction transaction = verifyAndGet(atResp);
        String cc = "client=" + transaction.getClient();
        info("5.a. got access token " + cc);

        preprocess(new TransactionState(httpServletRequest, httpServletResponse, atResp.getParameters(), transaction));

        debug("5.a. access token = " + atResp.getAccessToken() + " for verifier = " + v);
        transaction.setAuthGrantValid(false);
        transaction.setAccessToken(atResp.getAccessToken());
        transaction.setAccessTokenValid(true);

        try {
            getTransactionStore().save(transaction);
            info("5.a. updated transaction state for " + cc + ", sending response to client");

        } catch (GeneralException e) {
            throw new ServletException("Error saving transaction", e);
        }
      //  atResp.write(httpServletResponse);
        info("5.b. done with access token exchange with " + cc);
        IssuerTransactionState transactionState = new IssuerTransactionState(httpServletRequest,
                httpServletResponse,
                atResp.getParameters(),
                transaction,
                atResp);
        postprocess(transactionState);
        return transactionState;
    }

}
