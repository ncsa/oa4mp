package org.oa4mp.server.loader.oauth2.storage.transactions;

import org.oa4mp.server.api.admin.transactions.DSTransactionKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/28/14 at  5:22 PM
 */
public class OA2TransactionKeys extends DSTransactionKeys {
    public OA2TransactionKeys() {
        callbackUri("callback_uri");
        verifier("verifier_token");
        clientKey("client_id");
    }

    protected String authTime = "auth_time";
    protected String atJWT = "at_jwt";
    protected String authzGrantLifetime = "authz_grant_lifetime";
    protected String consentPageOK = "consent_page_ok";
    protected String expiresIn = "expires_in";
    // https://github.com/ncsa/oa4mp/issues/128
    protected String idTokenIdentifier  = "id_token_identifier";
    protected String isRFC8628  = "is_rfc_8628";
    protected String proxyID  = "proxy_id";
    protected String refreshToken = "refresh_token";
    protected String refreshTokenLifetime = "refresh_token_lifetime";
    protected String refreshTokenExpiresAt = "refresh_token_expires_at";
    protected String idTokenLifetime = "id_token_lifetime";
    protected String refreshTokenValid = "refresh_token_valid";
    protected String reqState = "req_state";
    protected String rtJWT = "rt_jwt";
    protected String scopes = "scopes";
    protected String states = "states";
    protected String userCode  = "user_code";
    protected String validatedScopes  = "validated_scopes";
    /*
     If you add keys or change these, you need to update TransactionStemMC or QDL support will break
     */

    public String consentPageOK(String... x) {
        if (0 < x.length) consentPageOK = x[0];
        return consentPageOK;
    }
    public String idTokenIdentifier(String... x) {
        if (0 < x.length) idTokenIdentifier = x[0];
        return idTokenIdentifier;
    }

    public String idTokenLifetime(String... x) {
        if (0 < x.length) idTokenLifetime = x[0];
        return idTokenLifetime;
    }

    public String rtJWT(String... x) {
        if (0 < x.length) rtJWT = x[0];
        return rtJWT;
    }

    public String atJWT(String... x) {
        if (0 < x.length) atJWT = x[0];
        return atJWT;
    }

    public String proxyID(String... x) {
        if (0 < x.length) proxyID = x[0];
        return proxyID;
    }
    public String userCode(String... x) {
        if (0 < x.length) userCode = x[0];
        return userCode;
    }

    public String validatedScopes(String... x) {
        if (0 < x.length) validatedScopes = x[0];
        return validatedScopes;
    }

    public String isRFC8628(String... x) {
        if (0 < x.length) isRFC8628 = x[0];
        return isRFC8628;
    }

    public String authzGrantLifetime(String... x) {
        if (0 < x.length) authzGrantLifetime = x[0];
        return authzGrantLifetime;
    }

    public String reqState(String... x) {
        if (0 < x.length) reqState = x[0];
        return reqState;
    }

    public String refreshTokenLifetime(String... x) {
        if (0 < x.length) refreshTokenLifetime = x[0];
        return refreshTokenLifetime;
    }

    public String refreshTokenExpiresAt(String... x) {
        if (0 < x.length) refreshTokenExpiresAt = x[0];
        return refreshTokenExpiresAt;
    }

    public String refreshToken(String... x) {
        if (0 < x.length) refreshToken = x[0];
        return refreshToken;
    }

    public String states(String... x) {
        if (0 < x.length) states= x[0];
        return states;
    }

    public String refreshTokenValid(String... x) {
        if (0 < x.length) refreshTokenValid = x[0];
        return refreshTokenValid;
    }

    public String expiresIn(String... x) {
        if (0 < x.length) expiresIn = x[0];
        return expiresIn;
    }


    public String scopes(String... x) {
        if (0 < x.length) scopes = x[0];
        return scopes;
    }
    public String authTime(String... x) {
        if (0 < x.length) authTime = x[0];
        return authTime;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys =  super.allKeys();
        allKeys.add(atJWT());
        allKeys.add(authTime());
        allKeys.add(authzGrantLifetime());
        allKeys.add(expiresIn());
        allKeys.add(idTokenIdentifier());
        allKeys.add(idTokenLifetime());
        allKeys.add(isRFC8628());
        allKeys.add(proxyID());
        allKeys.add(refreshToken());
        allKeys.add(refreshTokenExpiresAt());
        allKeys.add(refreshTokenLifetime());
        allKeys.add(refreshTokenValid());
        allKeys.add(reqState());
        allKeys.add(rtJWT());
        allKeys.add(scopes());
        allKeys.add(states());
        allKeys.add(userCode());
        allKeys.add(validatedScopes());
        return allKeys;

    }
}
