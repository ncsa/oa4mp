package org.oa4mp.delegation.common.token;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/21/14 at  3:45 PM
 */
public interface RefreshToken extends NewToken{
    /**
     * The time interval, in milliseconds, that this token remains valid.
     * <h3>Caveat</h3>
     * some protocols return this in seconds, so make sure it is in the proper units
     * before putting it in a refresh token.
     * @return
     */
/*    public long getExpiresIn();
    public void setExpiresIn(long expiresIn);*/
}
