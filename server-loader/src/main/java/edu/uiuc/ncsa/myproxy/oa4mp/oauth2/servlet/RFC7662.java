package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The token introspection servlet
 * This implements <a href="https://tools.ietf.org/html/rfc7662">RFC7662</a>
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/20 at  2:10 PM
 */
public class RFC7662 extends TokenManagerServlet {

    @Override
    protected void doIt(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        State state;
        TokenImpl token;
        try {
            if (!OA2HeaderUtils.getAuthHeader(req, OA2HeaderUtils.BASIC_HEADER).isEmpty()) {
                state = checkBasic(req);
            } else {
                state = checkBearer(req);
            }
        } catch (OA2GeneralError x) {
            info("Got exception checking bearer/basic header:" + x.getMessage() );

            // This means that the token supplied does not exist (usually) or it is not really
            // a valid token. This servlet is not to throw exceptions except in very narrow cases
            // but to return false instead.
            JSONObject jsonObject = new JSONObject();
            jsonObject.put(ACTIVE, false);
            writeOK(resp, jsonObject);
            return;

        }
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(state.transaction.getOA2Client());
        if (state.txRecord != null) {
            debugger.trace(this, "introspect, token in exchange record = \"" + state.txRecord.getIdentifier() + "\"");
            JSONObject jsonObject = new JSONObject();
            jsonObject.put(ACTIVE, state.txRecord.isValid());
            if (jsonObject.getBoolean(ACTIVE)) {
                populateResponse(state, jsonObject);
            }
            debugger.trace(this, "token is " + (jsonObject.getBoolean(ACTIVE)?"":"not") + " active");
            writeOK(resp, jsonObject);
            return;
        }

        if (state.transaction != null) {
            debugger.trace(this, "introspect, from transaction = \"" + state.transaction.getIdentifier() + "\"");
            JSONObject jsonObject = new JSONObject();
            if (state.isAT) {
                jsonObject.put(ACTIVE, state.transaction.isAccessTokenValid());
            } else {
                jsonObject.put(ACTIVE, state.transaction.isRefreshTokenValid());
            }
            if (jsonObject.getBoolean(ACTIVE)) {
                populateResponse(state, jsonObject);
            }
            debugger.trace(this, "token is " + (jsonObject.getBoolean(ACTIVE)?"":"not") + " active");

            writeOK(resp, jsonObject);
            return;
        }

        debugger.trace(this, "default case: token is not active");

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(ACTIVE, false);
        writeOK(resp, jsonObject);
        return;


    }

    /**
     * Used for the case that the response is for an active token.
     *
     * @param state
     * @param json
     */
    protected void populateResponse(State state, JSONObject json) {
        if (!json.containsKey(ACTIVE)) {
            return;
        }
        if (!json.getBoolean(ACTIVE)) {
            return;
        }
        TokenImpl token = state.isAT ? state.accessToken : state.refreshToken;


        if (token.isJWT()) {
            return;
        } // They have all this info in the payload of the JWT.
        if (state.txRecord != null) {
            TXRecord txr = state.txRecord;
            json.put(OA2Claims.AUDIENCE, txr.getAudience());
            if (txr.getScopes() == null || txr.getScopes().isEmpty()) {
                json.put(OA2Constants.SCOPE, state.transaction.getScopes());
            } else {
                json.put(OA2Constants.SCOPE, txr.getScopes());
            }
            json.put(OA2Claims.EXPIRATION, txr.getExpiresAt() / 1000);
            json.put(OA2Claims.ISSUED_AT, txr.getIssuedAt() / 1000);
            json.put(OA2Claims.NOT_VALID_BEFORE, token.getIssuedAt() / 1000);
            json.put(OA2Claims.ISSUER, txr.getIssuer());
            json.put(OA2Claims.JWT_ID, token.getJti().toString());
            json.put(USERNAME, state.transaction.getUsername());
            json.put(OA2Constants.CLIENT_ID, state.transaction.getOA2Client().getIdentifierString());
            json.put(TOKEN_TYPE, (token instanceof AccessToken) ? RFC8693Constants.ACCESS_TOKEN_TYPE : RFC8693Constants.REFRESH_TOKEN_TYPE);
            return;
        }

        OA2ServiceTransaction transaction = state.transaction;
        long authTime = transaction.getAuthTime().getTime();
        if (state.isAT) {
            json.put(OA2Claims.AUDIENCE, transaction.getAudience());
            json.put(OA2Constants.SCOPE, transaction.getScopes());
            json.put(OA2Claims.EXPIRATION, (authTime + transaction.getAccessTokenLifetime()) / 1000);
        }
        // In a standard OA4MP token (this case) there is no issuer outside of the service itself.
        if (transaction.getUserMetaData().containsKey(OA2Claims.ISSUER)) {
            json.put(OA2Claims.ISSUER, transaction.getUserMetaData().getString(OA2Claims.ISSUER));
        }
        json.put(OA2Claims.EXPIRATION, token.getIssuedAt() / 1000);
        json.put(OA2Claims.ISSUED_AT, authTime / 1000);
        json.put(OA2Claims.NOT_VALID_BEFORE, token.getIssuedAt() / 1000);
        json.put(OA2Claims.JWT_ID, token.getJti().toString());
        json.put(USERNAME, state.transaction.getUsername());
        json.put(OA2Constants.CLIENT_ID, state.transaction.getOA2Client().getIdentifierString());
        json.put(TOKEN_TYPE, (token instanceof AccessToken) ? RFC8693Constants.ACCESS_TOKEN_TYPE : RFC8693Constants.REFRESH_TOKEN_TYPE);
    }

}
