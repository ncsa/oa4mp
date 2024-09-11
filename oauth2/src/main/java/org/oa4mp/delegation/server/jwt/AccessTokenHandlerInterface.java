package org.oa4mp.delegation.server.jwt;

import org.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/24/20 at  7:28 AM
 */
public interface AccessTokenHandlerInterface extends PayloadHandler {
    /**
     * The actual simple access token (usually used as the identifier for the claims-based AT.
     * To get the signed claims, invoke {@link #getSignedPayload(JSONWebKey, String)} (JSONWebKey)}.
     * @return
     */
    AccessToken getAccessToken();
    void setAccessToken(AccessToken accessToken);
    JSONObject getUserMetaData();

    JSONObject getPayload();
}
