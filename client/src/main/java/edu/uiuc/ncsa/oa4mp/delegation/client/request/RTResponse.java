package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/14 at  11:19 AM
 */
public class RTResponse extends ATResponse{
    public RTResponse(AccessTokenImpl accessToken) {
        super(accessToken);
    }

    public RTResponse(AccessTokenImpl accessToken, RefreshTokenImpl refreshToken) {
        super(accessToken);
        this.refreshToken = refreshToken;
    }

    public RefreshTokenImpl getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshTokenImpl refreshToken) {
        this.refreshToken = refreshToken;
    }

    RefreshTokenImpl refreshToken;
}
