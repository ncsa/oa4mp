package edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/24/20 at  7:28 AM
 */
public interface AccessTokenHandlerInterface extends PayloadHandler {
    /**
     * The actual simple access token (usually used as the identifier for the claims-based AT.
     * To get the signed claims, invoke {@link #getSignedAT(JSONWebKey}.
     * @return
     */
    AccessToken getAccessToken();
    void setAccessToken(AccessToken accessToken);
    AccessToken getSignedAT(JSONWebKey key);
    AccessToken getSignedAT(JSONWebKey key, String headerType); // CIL-1112, support for RFC9068
}
