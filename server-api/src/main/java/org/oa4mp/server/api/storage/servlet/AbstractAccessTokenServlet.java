package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.request.ATRequest;
import org.oa4mp.delegation.server.request.ATResponse;
import org.oa4mp.delegation.common.servlet.TransactionState;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/13 at  1:37 PM
 */
public abstract class AbstractAccessTokenServlet extends OA4MPServlet {
    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
 //       printAllParameters(httpServletRequest);
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
        return getIssuerTransactionState(httpServletRequest, httpServletResponse,  updatedAG, transaction, GenericStoreUtils.toXML(getTransactionStore(), transaction));
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
                                                             ServiceTransaction transaction,
                                                               XMLMap backup) throws Throwable {
         return getIssuerTransactionState(
                 httpServletRequest,
                 httpServletResponse,
                 updatedAG,
                 transaction,
                 backup,
                 false);
    }
    protected IssuerTransactionState getIssuerTransactionState(HttpServletRequest httpServletRequest,
                                                             HttpServletResponse httpServletResponse,
                                                             AuthorizationGrant updatedAG,
                                                             ServiceTransaction transaction,
                                                               XMLMap backup,
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

        preprocess(new TransactionState(httpServletRequest, httpServletResponse, atResp.getParameters(), transaction, backup));

        debugger.trace(this,"5.a. access token = " + atResp.getAccessToken() + (v!=null?(" for verifier = " + v):""));
        transaction.setAuthGrantValid(false);
        transaction.setAccessToken(atResp.getAccessToken());
        transaction.setAccessTokenValid(true);

        try {
            getTransactionStore().save(transaction);
            debugger.info(this,"5.a. updated transaction state for " + cc + ", sending response to client");

        } catch (GeneralException e) {
            throw new ServletException("Error saving transaction", e);
        }
        //  atResp.write(httpServletResponse);
        debugger.info(this,"5.b. done with access token exchange with " + cc);
        IssuerTransactionState transactionState = new IssuerTransactionState(httpServletRequest,
                httpServletResponse,
                atResp.getParameters(),
                transaction,
                backup,
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
