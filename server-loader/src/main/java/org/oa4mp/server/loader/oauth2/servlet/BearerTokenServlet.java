package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.server.JWTUtil;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.OA2GeneralError;
import org.oa4mp.delegation.server.OA2RedirectableError;
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
public abstract class BearerTokenServlet extends OA4MPServlet {

    /**
     * Find the transaction associated with the access token. Note that this will not return
     * a null, but will throw a general error that the token was not found.
     * @param at
     * @param state
     * @return
     * @throws IOException
     */
    protected OA2ServiceTransaction findTransaction(AccessTokenImpl at, TokenManagerServlet.State state) throws IOException {
        // The access token is sent in the authorization header and should look like
           // Bearer oa4mp:...


           // Need to look this up by its jti if it's not a basic access token.
           OA2ServiceTransaction transaction = (OA2ServiceTransaction) getTransactionStore().get(new AccessTokenImpl(at.getJti()));
           OA2SE oa2SE = (OA2SE) getServiceEnvironment();
           // See if this is an exchanged token
           if (transaction == null) {
               // if there is no such transaction found, then this is probably from a previous exchange. Go find it
               TXRecord oldTXR = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(at.getJti()));
               if (oldTXR == null) {
                   ServletDebugUtil.trace(this, "No transaction found, no TXRecord found for access token = " + at);
                   OA2GeneralError ge = new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                           "token not found",
                           HttpStatus.SC_UNAUTHORIZED,
                           null);
                   ge.setForensicMessage("Error getting exchange record for the access token \"" + at.getJti() + "\"");
                   throw ge;
               }
               transaction = (OA2ServiceTransaction) getTransactionStore().get(oldTXR.getParentID());

               if (!oldTXR.isValid()) {
                   OA2GeneralError x = new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                           "The token is not valid",
                           HttpStatus.SC_UNAUTHORIZED,
                           null, transaction==null?null:transaction.getClient());
                   x.setForensicMessage("The token is not valid");
                   throw x;
               }
               if (oldTXR.getExpiresAt() < System.currentTimeMillis()) {
                   OA2GeneralError x =  new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                           "The token has expired",
                           HttpStatus.SC_UNAUTHORIZED,
                           null, transaction==null?null:transaction.getClient());
                   x.setForensicMessage("The token has expired");
                   throw x;
               }
               state.txRecord = oldTXR;
               state.transaction = transaction;
           }else{
               state.transaction = transaction;
           }
           // check that
           if (transaction == null) {
               OA2GeneralError x = new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                       "no transaction found.",
                       HttpStatus.SC_BAD_REQUEST,
                       null);
               x.setForensicMessage("no transaction found.");
               throw x;
           }
           // Now, we finally have the transaction and are in a position to check the signature
           // of the token. we don't have a good way of doing this without looking into the transaction
           // to find any VO. Since VOs manage their keys, and the call to this endpoint only requires
           // the access token (which typically does nto have any information in its header about OA4MP VO')
           // there is no good way to do this until now.

           //CIL-974 fix:

           if(at.isJWT()){
               JSONWebKeys keys = ((OA2SE) getServiceEnvironment()).getJsonWebKeys();
               VirtualIssuer vo = oa2SE.getVI(transaction.getClient().getIdentifier());

               if(vo != null){
                    keys = vo.getJsonWebKeys();
               }
               try{
                    JWTUtil.verifyAndReadJWT(at.getToken(), keys);
                    // all we care about is that the right set of keys works for this.
               }catch(Throwable t){
                   ServletDebugUtil.trace(this, "Failed to verify access token JWT for " + at);
                   OA2GeneralError x = new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                                               "invalid access token",
                                               HttpStatus.SC_BAD_REQUEST,
                                               null, transaction.getClient());
                   x.setForensicMessage("invalid access token");
                   throw x;
               }
           }
           // Check expiration after verifying it since some of the state of the transaction is returned
           // if it is merely expired. If it is invalid, then there should be no information returned.
           if(at.isExpired()){
               OA2RedirectableError x = new OA2RedirectableError(OA2Errors.INVALID_TOKEN,
                       "expired token.",
                       HttpStatus.SC_BAD_REQUEST,
                       transaction.getRequestState(),
                       transaction.getCallback(),
                       transaction.getClient());
               x.setForensicMessage("expired token.");
               throw x;

           }
           
          return transaction;

    }
}
