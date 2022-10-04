package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/14 at  10:27 AM
 */
public class RTIResponse extends IDTokenResponse {
    public RTIResponse(AccessTokenImpl accessToken,
                       RefreshTokenImpl refreshToken,
                       boolean isOIDC) {
        super(accessToken, refreshToken,isOIDC);
    }

    @Override
    public String toString() {
        return "RTIResponse{" +
                "accessToken=" + accessToken +
                ", refreshToken=" + refreshToken +
                ", signToken=" + signToken +
                ", claims=" + claims +
                ", supportedScopes=" + supportedScopes +
                '}';
    }
}
