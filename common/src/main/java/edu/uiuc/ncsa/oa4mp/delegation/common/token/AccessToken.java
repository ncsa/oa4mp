package edu.uiuc.ncsa.oa4mp.delegation.common.token;


/**
 * An access token for delegation.  This is used later to retrieve the {@link ProtectedAsset}.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 11, 2011 at  4:10:17 PM
 */
public interface AccessToken extends NewToken {
    /**
     * An <b>optional</b> shared secret for those implementations that support or require it. Ignored if
     * unused.
     *
     */
/*    String getSharedSecret();
    void setSharedSecret(String sharedSecret);*/
}
