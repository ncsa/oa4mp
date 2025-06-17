package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.api.storage.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
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

    protected abstract ATRequest getATRequest(HttpServletRequest request, ServiceTransaction transaction, OA2Client client);

    protected abstract ServiceTransaction getTransaction(AuthorizationGrant ag, HttpServletRequest req) throws ServletException;

    @Override
    public OA2Client getClient(HttpServletRequest request) {
        return (OA2Client) super.getClient(request);
    }

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

        return getIssuerTransactionState(httpServletRequest,
                httpServletResponse,
                updatedAG,
                transaction,
                (OA2Client)client,
                GenericStoreUtils.toXML(getTransactionStore(), transaction));
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
                                                               OA2Client client,
                                                               XMLMap backup) throws Throwable {
         return getIssuerTransactionState(
                 httpServletRequest,
                 httpServletResponse,
                 updatedAG,
                 transaction,
                 client,
                 backup,
                 false);
    }
    protected IssuerTransactionState getIssuerTransactionState(HttpServletRequest httpServletRequest,
                                                             HttpServletResponse httpServletResponse,
                                                             AuthorizationGrant updatedAG,
                                                             ServiceTransaction transaction,
                                                               OA2Client client,
                                                               XMLMap backup,
                                                               boolean isRFC8628) throws Throwable {


        if(updatedAG != null){
            // This allows for maintaining version 4.x to 5.x token compatibility
            transaction.setAuthorizationGrant(updatedAG);
        }
        MetaDebugUtil debugger = createDebugger(transaction.getClient());
        ATRequest atRequest = getATRequest(httpServletRequest, transaction, client);

        atRequest.setAuthorizationGrant(updatedAG);
        ATResponse atResp = (ATResponse) getATI().process(atRequest);
        if(!isRFC8628) {
            transaction = verifyAndGet(atResp);
        }
        String cc = "client=" + transaction.getClient();
        debugger.info(this,"5.a. got access token " + cc);

        preprocess(new TransactionState(httpServletRequest, httpServletResponse, atResp.getParameters(), transaction, backup));

        transaction.setAuthGrantValid(false);
        transaction.setAccessToken(atResp.getAccessToken());
        transaction.setAccessTokenValid(true);

        // CIL-1268 fix: Removed transaction save here that was too early.

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
