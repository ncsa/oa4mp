package org.oa4mp.delegation.server.server;

import org.oa4mp.delegation.server.request.ATResponse;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * OIDC server response for request for access token
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:10 PM
 */
public class ATIResponse2 extends IDTokenResponse implements ATResponse {
    public ATIResponse2(AccessTokenImpl accessToken,
                        RefreshTokenImpl refreshToken,
                        boolean isOIDC) {
        super(accessToken,refreshToken,isOIDC);
    }


}
