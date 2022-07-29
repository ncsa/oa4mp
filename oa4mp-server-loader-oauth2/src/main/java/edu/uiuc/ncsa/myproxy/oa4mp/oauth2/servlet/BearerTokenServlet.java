package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.JWTUtil;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2RedirectableError;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.apache.http.HttpStatus;

import java.io.IOException;

/**
 * For endpoints that use bearer tokens. The issue is that bearer tokens may be JWTs and
 * have to be verified, but the information to do so is not available until the transaction
 * is recovered -- which may also be the result of a previous token exchange. Therefore
 * this will do all the checks in a single method to get the right thing. Used
 * by the {@link UserInfoServlet}, {@link RFC7662} and {@link RFC7009}.
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  12:19 PM
 */
public abstract class BearerTokenServlet extends MyProxyDelegationServlet {

    protected OA2ServiceTransaction findTransaction(AccessTokenImpl at, TokenManagerServlet.State state) throws IOException {
        // The access token is sent in the authorization header and should look like
           // Bearer oa4mp:...


           // Need to look this up by its jti if its not a basic access token.
           OA2ServiceTransaction transaction = (OA2ServiceTransaction) getTransactionStore().get(new AccessTokenImpl(at.getJti()));
           OA2SE oa2SE = (OA2SE) getServiceEnvironment();
           // See if this is an exchanged token
           if (transaction == null) {
               // if there is no such transaction found, then this is probably from a previous exchange. Go find it
               TXRecord oldTXR = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(at.getJti()));
               if (oldTXR == null) {
                   ServletDebugUtil.trace(this, "No transaction found, no TXRecord found for access token = " + at);
                   throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                           "token not found",
                           HttpStatus.SC_UNAUTHORIZED,
                           null);
               }
               if (!oldTXR.isValid()) {
                   throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                           "The token is not valid",
                           HttpStatus.SC_UNAUTHORIZED,
                           null);
               }
               if (oldTXR.getExpiresAt() < System.currentTimeMillis()) {
                   throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                           "The token has expired",
                           HttpStatus.SC_UNAUTHORIZED,
                           null);
               }
               transaction = (OA2ServiceTransaction) getTransactionStore().get(oldTXR.getParentID());
               state.txRecord = oldTXR;
               state.transaction = transaction;
           }else{
               state.transaction = transaction;
           }
           // check that
           if (transaction == null) {
               throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                       "no transaction found.",
                       HttpStatus.SC_BAD_REQUEST,
                       null);
           }
           // Now, we finally have the transaction and are in a position to check the signature
           // of the token. we don't have a good way of doing this without looking into the transaction
           // to find any VO. Since VOs manage their keys, and the call to this endpoint only requires
           // the access token (which typically does nto have any information in its header about OA4MP VO')
           // there is no good way to do this until now.

           //CIL-974 fix:

           if(at.isJWT()){
               JSONWebKeys keys = ((OA2SE) getServiceEnvironment()).getJsonWebKeys();
               VirtualOrganization vo = oa2SE.getVO(transaction.getClient().getIdentifier());

               if(vo != null){
                    keys = vo.getJsonWebKeys();
               }
               try{
                    JWTUtil.verifyAndReadJWT(at.getToken(), keys);
                    // all we care about is that the right set of keys works for this.
               }catch(Throwable t){
                   ServletDebugUtil.trace(this, "Failed to verify access token JWT for " + at);
                   throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                                               "invalid access token",
                                               HttpStatus.SC_BAD_REQUEST,
                                               null);
               }
           }
           // Check expiration after verifying it since some of the state of the transaction is returned
           // if it is merely expired. If it is invalid, then there should be no information returned.
           if(at.isExpired()){
               throw new OA2RedirectableError(OA2Errors.INVALID_TOKEN,
                       "expired token.",
                       HttpStatus.SC_BAD_REQUEST,
                       transaction.getRequestState(),
                       transaction.getCallback());

           }
           
          return transaction;

    }
}
