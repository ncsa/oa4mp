package org.oa4mp.delegation.common.token;

/**
 * An authorization grant. This will be exchanged later for an {@link AccessToken}
 * <p>Created by Jeff Gaynor<br>
 * on Mar 11, 2011 at  4:10:50 PM
 */
public interface AuthorizationGrant extends NewToken {
    /**
     * An <b>optional</b> shared secret for those implementations that support or require it. Ignored if
     * unused.
     *
     * @return
     */
/*    String getSharedSecret();

    void setSharedSecret(String sharedSecret);*/
}
