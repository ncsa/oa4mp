package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSTransactionKeys;

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
    protected String authzGrantLifetime = "authz_grant_lifetime";
    protected String expiresIn = "expires_in";
    protected String isRFC8628  = "is_rfc_8628";
    protected String refreshToken = "refresh_token";
    protected String refreshTokenLifetime = "refresh_token_lifetime";
    protected String refreshTokenValid = "refresh_token_valid";
    protected String reqState = "req_state";
    protected String scopes = "scopes";
    protected String states = "states";
    protected String userCode  = "user_code";
    protected String validatedScopes  = "validated_scopes";
    /*
     If you add keys or change these, you need to up date TransactionStemMC or QDL support will break
     */

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
        allKeys.add(authTime());
        allKeys.add(authzGrantLifetime());
        allKeys.add(expiresIn());
        allKeys.add(isRFC8628());
        allKeys.add(refreshToken());
        allKeys.add(refreshTokenLifetime());
        allKeys.add(refreshTokenValid());
        allKeys.add(reqState());
        allKeys.add(states());
        allKeys.add(scopes());
        allKeys.add(userCode());
        allKeys.add(validatedScopes());
        return allKeys;

    }
}
