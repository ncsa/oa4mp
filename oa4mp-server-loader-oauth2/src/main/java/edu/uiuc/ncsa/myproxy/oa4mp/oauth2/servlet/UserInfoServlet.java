package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UII2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIRequest2;
import edu.uiuc.ncsa.security.oauth_2_0.server.UIIResponse2;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

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
        try {
            JSONWebKeys keys = ((OA2SE) getServiceEnvironment()).getJsonWebKeys();
            OA2TokenForge tokenForge = ((OA2TokenForge) getServiceEnvironment().getTokenForge());

            JSONObject sciTokens = JWTUtil.verifyAndReadJWT(at.getToken(), keys);
            at = tokenForge.getAccessToken(sciTokens.getString(JWT_ID));
        } catch (Throwable tt) {
            // didn't work, so its just a regular access token.
        }

        // Need to look this up by its jti if its not a basic access token.
        OA2ServiceTransaction transaction = (OA2ServiceTransaction) getTransactionStore().get(at);
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        // See if this is an exchanged token
        if (transaction == null) {
            // if there is no such transaction found, then this is probably from a previous exchange. Go find it
            TXRecord oldTXR = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(at.getToken()));
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
            if (oldTXR != null) {
                transaction = (OA2ServiceTransaction) getTransactionStore().get(oldTXR.getParentID());
            }
        }
        // check that
        if (transaction == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "no transaction found.",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }
        if (!transaction.getFlowStates().userInfo) {
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                    "access denied", HttpStatus.SC_UNAUTHORIZED,
                    transaction.getRequestState(),
                    transaction.getCallback());
        }
      /*  if (transaction.getOA2Client().isPublicClient()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "public client not authorized to access user information", HttpStatus.SC_UNAUTHORIZED);
        }*/

        if (!transaction.isAccessTokenValid()) {
            throw new OA2RedirectableError(OA2Errors.INVALID_TOKEN,
                    "invalid access token.",
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState(),
                    transaction.getCallback());
        }
        try {
            checkTimestamp(at.getToken());
        } catch (InvalidTimestampException itx) {
            throw new OA2RedirectableError(OA2Errors.INVALID_TOKEN,
                    "expired token.",
                    HttpStatus.SC_BAD_REQUEST,
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

    protected String getRawAT(HttpServletRequest request) {
        String rawAT = null;
        String headerAT = HeaderUtils.getBearerAuthHeader(request);
        String paramAT = getFirstParameterValue(request, ACCESS_TOKEN);

        if (paramAT == null) {
            if (headerAT == null) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "missing access token",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            rawAT = headerAT;
        } else {
            if (headerAT == null) {
                rawAT = paramAT;
            } else {
                if (!paramAT.equals(headerAT)) {
                    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                            "multiple access tokens",
                            HttpStatus.SC_BAD_REQUEST,
                            null);
                }
                rawAT = paramAT;
            }
        }
        // now we have to take into account that this might not be a basic token.
        // Note that we do not care at this point about anything in the token but
        //  its signature (must be valid, so no tampering allowed) and JTI.
        try {
            OA2SE oa2se = (OA2SE) getServiceEnvironment();

            JSONObject sciToken = JWTUtil2.verifyAndReadJWT(rawAT, oa2se.getJsonWebKeys());
            if (sciToken.containsKey(JWT_ID)) {
                return sciToken.get(JWT_ID).toString();
            }
        } catch (Throwable t) {
            // do nothing. Assume it is a standard access token, not a sci token.
        }
        return rawAT;
    }

    protected AccessToken getAT(HttpServletRequest request) {
        String rawAt = getRawAT(request);
        if(TokenUtils.isBase64(rawAt)){
            rawAt = TokenUtils.decodeToken(rawAt);
        }
        return new AccessTokenImpl(URI.create(rawAt));
    }
}
