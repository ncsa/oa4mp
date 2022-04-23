package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.security.delegation.server.request.ATResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.Verifier;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/13 at  1:37 PM
 */
/*
 Note that this is replaces by {@link AbstractAccessTokenServlet}. That is from the
 OAuth 1 implementation and because it screws up clean inheritance for client access
 and using Authorization Basic, This has to be put here.
 */
public abstract class AbstractAccessTokenServlet2 extends MultiAuthServlet {
    // Ends up here because of Java package and module visibility requirements.
    public static Cleanup<Identifier, TXRecord> txRecordCleanup = null;

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
  //      printAllParameters(httpServletRequest);
        doDelegation(httpServletRequest, httpServletResponse);
    }

    protected abstract ATRequest getATRequest(HttpServletRequest request, ServiceTransaction transaction);

    protected abstract ServiceTransaction getTransaction(AuthorizationGrant ag, HttpServletRequest req) throws ServletException;

    /**
     * Contract: if the token gets updated (might have to because of changes to token versions), return it.
     * If no changes, return null.
     * @param ag
     * @return
     */
    protected abstract AuthorizationGrant checkAGExpiration(AuthorizationGrant ag);

    protected IssuerTransactionState doDelegation(Client client, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable, ServletException {
        createDebugger(client).info(this,"5.a. Starting access token exchange");
        info("5.a. Starting access token exchange");
        AuthorizationGrant ag = getServiceEnvironment().getTokenForge().getAuthorizationGrant(httpServletRequest);
        AuthorizationGrant updatedAG  = checkAGExpiration(ag);
        ServiceTransaction transaction = getTransaction(ag, httpServletRequest);
        return getIssuerTransactionState(httpServletRequest, httpServletResponse,  updatedAG, transaction);
    }

    /**
     * Default for standard token endpoint call.
     * @param httpServletRequest
     * @param httpServletResponse
     * @param updatedAG
     * @param transaction
     * @return
     * @throws Throwable
     */
    protected IssuerTransactionState getIssuerTransactionState(HttpServletRequest httpServletRequest,
                                                             HttpServletResponse httpServletResponse,
                                                             AuthorizationGrant updatedAG,
                                                             ServiceTransaction transaction) throws Throwable {
         return getIssuerTransactionState(
                 httpServletRequest,
                 httpServletResponse,
                 updatedAG,
                 transaction,
                 false);
    }
    protected IssuerTransactionState getIssuerTransactionState(HttpServletRequest httpServletRequest,
                                                             HttpServletResponse httpServletResponse,
                                                             AuthorizationGrant updatedAG,
                                                             ServiceTransaction transaction,
                                                               boolean isRFC8628) throws Throwable {


        if(updatedAG != null){
            // This allows for maintaining version 4.x to 5.x token compatibility
            transaction.setAuthorizationGrant(updatedAG);
        }
        MetaDebugUtil debugger = createDebugger(transaction.getClient());
        ATRequest atRequest = getATRequest(httpServletRequest, transaction);

        Verifier v = getServiceEnvironment().getTokenForge().getVerifier(httpServletRequest);
        atRequest.setVerifier(v); // can be null
        atRequest.setAuthorizationGrant(updatedAG);
        ATResponse atResp = (ATResponse) getATI().process(atRequest);
        if(!isRFC8628) {
            transaction = verifyAndGet(atResp);
        }
        String cc = "client=" + transaction.getClient();
        debugger.info(this,"5.a. got access token " + cc);

        preprocess(new TransactionState(httpServletRequest, httpServletResponse, atResp.getParameters(), transaction));

        debugger.trace(this,"5.a. access token = " + atResp.getAccessToken() + (v!=null?(" for verifier = " + v):""));
        transaction.setAuthGrantValid(false);
        transaction.setAccessToken(atResp.getAccessToken());
        transaction.setAccessTokenValid(true);

        // CIL-1268 fix: Removed transaction save here that was too early.

        debugger.info(this,"5.b. done with access token exchange with " + cc);
        IssuerTransactionState transactionState = new IssuerTransactionState(httpServletRequest,
                httpServletResponse,
                atResp.getParameters(),
                transaction,
                atResp);
        transactionState.setRfc8628(isRFC8628);
        postprocess(transactionState);
        return transactionState;
    }


    /**
     * Note that this method does <b>not</b> write the response (using the issuer response). You must
     * do that in your implementation after you have finished all processing. If we were to do that here,
     * the response would be written prematurely.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @return
     * @throws Throwable
     * @throws ServletException
     */
    protected IssuerTransactionState doDelegation(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable, ServletException {
        return doDelegation(getClient(httpServletRequest), httpServletRequest, httpServletResponse);
    }

}
