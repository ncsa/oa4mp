package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  12:04 PM
 */
public class OA2Asset extends Asset {
    public OA2Asset(Identifier identifier) {
        super(identifier);
    }
    AccessTokenImpl accessToken;
    RefreshTokenImpl refreshToken;

    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    Date issuedAt = new Date();

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    String state;

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    String nonce;

    public AccessTokenImpl getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessTokenImpl accessToken) {
        this.accessToken = accessToken;
    }


    public RefreshTokenImpl getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshTokenImpl refreshToken) {
        this.refreshToken = refreshToken;
    }


}
