package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.OA2TokenUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.server.UII2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIRequest2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIResponse2;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.EXPIRATION;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.ISSUED_AT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/4/13 at  11:09 AM
 */
public class UserInfoServlet extends MyProxyDelegationServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // The access token is sent in the authorization header and should look like
        // Bearer oa4mp:...

        AccessTokenImpl at = OA2TokenUtils.getAT(getRawAT(request));

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

        if (!transaction.getFlowStates().userInfo) {
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                    "access denied", HttpStatus.SC_UNAUTHORIZED,
                    transaction.getRequestState(),
                    transaction.getCallback());
        }



        UII2 uis = new UII2(oa2SE.getTokenForge(), getServiceEnvironment().getServiceAddress());
        UIIRequest2 uireq = new UIIRequest2(request, at);
        uireq.setUsername(getUsername(transaction));
        UIIResponse2 uiresp = (UIIResponse2) uis.process(uireq);
        // creates the token handler just to get the updated accounting information.
        IDTokenHandler idTokenHandler = new IDTokenHandler(new PayloadHandlerConfigImpl(
                ((OA2Client) transaction.getClient()).getIDTokenConfig(),
                oa2SE,
                transaction,
                null, // no token exchange record outside of token exchanges.
                null));
        idTokenHandler.refreshAccountingInformation();
        getTransactionStore().save(transaction);
        uiresp.getUserInfo().getMap().putAll(stripClaims(transaction.getUserMetaData()));
        uiresp.write(response);
    }

    /**
     * This strips out claims that should not be returned, such as the nonce, but are part of the original
     * id token.
     *
     * @param json
     * @return
     */
    protected JSONObject stripClaims(JSONObject json) {
        JSONObject r = new JSONObject();
        r.putAll(json);// new json object so we don't lose information and so we don't get concurrent update error
        String[] x = new String[]{ISSUED_AT, NONCE, EXPIRATION, EXPIRES_IN, AUTHORIZATION_TIME};
        for (String y : x) {
            r.remove(y);
        }
        return r;
    }

    /**
     * Override this if needed.
     *
     * @param transaction
     * @return
     */
    protected String getUsername(ServiceTransaction transaction) {
        return transaction.getUsername();
    }

    // not implemented.
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }



    /**
     * Gets the current raw access token from the header or throws an exception none is found.
     * @param request
     * @return
     */
    protected String getRawAT(HttpServletRequest request) {
        String headerAT = HeaderUtils.getBearerAuthHeader(request);
        String paramAT = getFirstParameterValue(request, ACCESS_TOKEN);
        if(headerAT == null && paramAT == null){
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                            "missing access token",
                            HttpStatus.SC_BAD_REQUEST,
                            null);
        }

        return headerAT == null?paramAT:headerAT;
    }
}
