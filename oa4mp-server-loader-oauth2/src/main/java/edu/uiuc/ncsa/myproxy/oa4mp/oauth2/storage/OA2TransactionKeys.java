package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.keys.DSTransactionKeys;

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

    protected String refreshToken = "refresh_token";
    protected String refreshTokenValid = "refresh_token_valid";
    protected String expiresIn = "expires_in";
    protected String nonce = "nonce";
    protected String scopes = "scopes";
    protected String authTime = "auth_time";

    public String refreshToken(String... x) {
        if (0 < x.length) refreshToken = x[0];
        return refreshToken;
    }

    public String refreshTokenValid(String... x) {
        if (0 < x.length) refreshTokenValid = x[0];
        return refreshTokenValid;
    }

    public String expiresIn(String... x) {
        if (0 < x.length) expiresIn = x[0];
        return expiresIn;
    }

    public String nonce(String... x) {
        if (0 < x.length) nonce = x[0];
        return nonce;
    }

    public String scopes(String... x) {
        if (0 < x.length) scopes = x[0];
        return scopes;
    }
    public String authTime(String... x) {
        if (0 < x.length) authTime = x[0];
        return authTime;
    }

}
