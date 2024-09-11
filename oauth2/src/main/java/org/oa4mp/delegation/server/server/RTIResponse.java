package org.oa4mp.delegation.server.server;

import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * Contains both an access token and refresh token.
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/14 at  10:27 AM
 */
public class RTIResponse extends IDTokenResponse {
    public RTIResponse(AccessTokenImpl accessToken,
                       RefreshTokenImpl refreshToken,
                       boolean isOIDC) {
        super(accessToken, refreshToken,isOIDC);
    }


}
