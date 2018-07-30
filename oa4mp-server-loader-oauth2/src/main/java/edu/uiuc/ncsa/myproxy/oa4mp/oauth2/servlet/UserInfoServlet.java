package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.server.UII2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIRequest2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIResponse2;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;
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

        AccessToken at = getAT(request);
        OA2ServiceTransaction transaction = (OA2ServiceTransaction) getTransactionStore().get(at);
        // check that
        if(!transaction.getFlowStates().userInfo){
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "user info access denied", HttpStatus.SC_UNAUTHORIZED);
        }
      /*  if (transaction.getOA2Client().isPublicClient()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "public client not authorized to access user information", HttpStatus.SC_UNAUTHORIZED);
        }*/
        if (transaction == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no transaction for the access token was found.", HttpStatus.SC_BAD_REQUEST);
        }
        if (!transaction.isAccessTokenValid()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "invalid access token.", HttpStatus.SC_BAD_REQUEST);
        }
        try {
            checkTimestamp(at.getToken());
        } catch (InvalidTimestampException itx) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "token expired.", HttpStatus.SC_BAD_REQUEST);
        }
        OA2SE oa2SE = (OA2SE)getServiceEnvironment();
        UII2 uis = new UII2(oa2SE.getTokenForge(), getServiceEnvironment().getServiceAddress());
        UIIRequest2 uireq = new UIIRequest2(request, at);
        uireq.setUsername(getUsername(transaction));
        UIIResponse2 uiresp = (UIIResponse2) uis.process(uireq);
        // add the claims we have stored.
        OA2ClaimsUtil claimsUtil = new OA2ClaimsUtil(oa2SE,transaction );
        transaction.setClaims(claimsUtil.setAccountingInformation(request, transaction.getClaims()));
        getTransactionStore().save(transaction);
        uiresp.getUserInfo().getMap().putAll(stripClaims(transaction.getClaims()));
        uiresp.write(response);
    }

    /**
     * This strips out claims that should not be returned, such as the nonce, but are part of the original
     * id token.
     * @param json
     * @return
     */
    protected JSONObject stripClaims(JSONObject json){
        JSONObject r = new JSONObject();
        r.putAll(json);// new json object so we don't lose information and so we don't get concurrent update error
        String[] x = new String[]{ISSUED_AT, NONCE,EXPIRATION,EXPIRES_IN,AUTHORIZATION_TIME};
        for(String y : x){
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
    protected String getRawAT(HttpServletRequest request){
        String rawAT = null;
             String headerAT = HeaderUtils.getBearerAuthHeader(request);
             String paramAT = getFirstParameterValue(request, ACCESS_TOKEN);

             if (paramAT == null) {
                 if (headerAT == null) {
                     throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no access token was sent.", HttpStatus.SC_BAD_REQUEST);
                 }
                 rawAT = headerAT;
             } else {
                 if (headerAT == null) {
                     rawAT = paramAT;
                 } else {
                     if (!paramAT.equals(headerAT)) {
                         throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "too many access tokens.", HttpStatus.SC_BAD_REQUEST);
                     }
                     rawAT = paramAT;
                 }
             }
        return rawAT;
    }
    protected AccessToken getAT(HttpServletRequest request) {
        return new AccessTokenImpl(URI.create(getRawAT(request)), null);
    }
}
