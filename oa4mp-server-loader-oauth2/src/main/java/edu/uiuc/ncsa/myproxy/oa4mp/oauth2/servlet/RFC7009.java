package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
            if (!HeaderUtils.getAuthHeader(req, HeaderUtils.BASIC_HEADER).isEmpty()) {
                state = checkBasic(req);
            } else {
                state = checkBearer(req);
            }
        }catch(OA2GeneralError x){
            DebugUtil.error(this, "Got exception checking bearer/basic header ",x);
            // if the token does not exist, return an OK == whatever it was they sent is
            // revoked.
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }

         // By this point the state object has the original transaction and request information in it,
        // plus it has the TX record if there is one.
        // Now we have enough to do what we need to.

        if(state.txRecord != null){
            state.txRecord.setValid(false);
            oa2SE.getTxStore().save(state.txRecord);
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }
        if(state.transaction == null){
            // no such record
            oa2SE.getTxStore().save(state.txRecord);
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }
        if(state.isAT) {
            state.transaction.setAccessTokenValid(false);
        }else{
            state.transaction.setRefreshTokenValid(false);
        }
        oa2SE.getTransactionStore().save(state.transaction);
        resp.setStatus(HttpStatus.SC_OK);
        return;
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
                        null);
            }
            oa2SE.getTransactionStore().remove(t.getIdentifier());
            return true;
        }
        return false;
    }


}
