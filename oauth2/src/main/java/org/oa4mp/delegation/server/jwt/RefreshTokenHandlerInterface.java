package org.oa4mp.delegation.server.jwt;

import org.oa4mp.delegation.common.token.RefreshToken;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/5/20 at  9:09 AM
 */
public interface RefreshTokenHandlerInterface extends PayloadHandler {
    RefreshToken getRefreshToken();
    void setRefreshToken(RefreshToken refreshToken);

}
