package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

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
