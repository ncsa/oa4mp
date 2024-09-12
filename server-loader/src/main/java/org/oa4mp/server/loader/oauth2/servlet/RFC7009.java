package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.delegation.common.token.impl.TokenImpl;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.OA2GeneralError;
import org.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * Token Revocation endpoint.  This implements <a href="https://tools.ietf.org/html/rfc7009">RFC7009</a>.
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/20 at  12:24 PM
 */
// NOTE that there is an older revocation servlet, but it does not handle JWTs as access tokens and a few other
// things. This is to replace that.
public class RFC7009 extends TokenManagerServlet {

    @Override
    protected void doIt(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        //printAllParameters(req);
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        State state;
        TokenImpl token;
        // Reminder: The next calls check that the requesting client is the same as the
        // one in the transaction, thus preventing hijacking.
        try {
            if (isRFC7523Client(req)) {
                // fixes https://github.com/ncsa/oa4mp/issues/115
                state = check7523(req);
            } else {
                if (!OA2HeaderUtils.getAuthHeader(req, OA2HeaderUtils.BASIC_HEADER).isEmpty()) {
                    state = checkBasic(req);
                } else {
                    state = checkBearer(req);
                }
            }
            if (state == null) {
                resp.setStatus(HttpStatus.SC_OK);
                logOK(req); // CIL-1722
                return;
            }
            // The previous call uses the bearer token (which is an access token) to recover the transactions
            // and any corresponding TXRecord. If this is for a refresh token, that has to be tracked down.
            if (!state.isAT && state.transaction != null) {
                List<? extends TXRecord> records = oa2SE.getTxStore().getByParentID(state.transaction.getIdentifier());
                for (TXRecord txRecord : records) {
                    if (txRecord.getIdentifierString().equals(state.refreshToken.getJti().toString())) {
                        state.txRecord = txRecord;
                        break;
                    }
                }
            }
        } catch (OA2GeneralError x) {
            DebugUtil.error(this, "Got exception checking bearer/basic header ", x);
            // if the token does not exist, return an OK == whatever it was they sent is
            // revoked.
            resp.setStatus(HttpStatus.SC_OK);
            logOK(req); // CIL-1722
            return;
        }


        // By this point the state object has the original transaction and request information in it,
        // plus it has the TX record if there is one.
        // Now we have enough to do what we need to.

        if (state.txRecord != null) {
            state.txRecord.setValid(false);
            oa2SE.getTxStore().save(state.txRecord);
            if (!state.isAT) {
                if (state.transaction.getRefreshToken().getJti().toString().equals(state.txRecord.getIdentifierString())) {
                    // Then there is a redundant record. Make sure both are marked.
                    // This can happen in very complex cases of multiple refreshes and exchanges, so just check here
                    // once and for all.
                    state.transaction.setRefreshTokenValid(false);
                    oa2SE.getTransactionStore().save(state.transaction);
                }
            }
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }
        if (state.transaction == null) {
            // No such record. Contract is to return ok.
            //oa2SE.getTxStore().save(state.txRecord);
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }
        if (state.isAT) {
            state.transaction.setAccessTokenValid(false);
        } else {
            state.transaction.setRefreshTokenValid(false);
        }
        oa2SE.getTransactionStore().save(state.transaction);
        resp.setStatus(HttpStatus.SC_OK);
        logOK(req); //CIL-1722
    }


    protected boolean checkToken(OA2Client requestingClient, String token) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        ServiceTransaction t = getTransFromToken(token);
        if (t != null) {
            // Finally, don't let some other client try to revoke other people's tokens.
            if (!t.getClient().getIdentifier().equals(requestingClient.getIdentifier())) {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "Unauthorized client",
                        HttpStatus.SC_UNAUTHORIZED,
                        null, requestingClient);
            }
            oa2SE.getTransactionStore().remove(t.getIdentifier());
            return true;
        }
        return false;
    }


}
