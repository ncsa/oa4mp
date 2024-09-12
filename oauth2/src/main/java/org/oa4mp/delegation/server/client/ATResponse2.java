package org.oa4mp.delegation.server.client;

import org.oa4mp.delegation.client.request.RTResponse;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.IDTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * Since the OAuth 2 protocol supports getting a refresh token back from the server with the access token,
 * we have to include it in this class.
 * <p>Created by Jeff Gaynor<br>
 * on 3/12/14 at  12:05 PM
 */
public class ATResponse2 extends RTResponse {
    public ATResponse2(AccessTokenImpl accessToken) {
        super(accessToken);
    }

    public ATResponse2(AccessTokenImpl accessToken, RefreshTokenImpl refreshToken, IDTokenImpl idToken) {
        super(accessToken,refreshToken, idToken);
    }
   // Note this is now mostly legacy since access tokens and refresh tokens may be returned
    // from a server. Unfortunately, Java package and inheritance restrictions make it hard
    // to simply dispose of this class.
}
