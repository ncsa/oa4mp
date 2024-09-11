package org.oa4mp.delegation.common.token;


import net.sf.json.JSONObject;

/**
 * An access token for delegation.  This is used later to retrieve the {@link ProtectedAsset}.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 11, 2011 at  4:10:17 PM
 */
public interface AccessToken extends NewToken {
    // Added payloads since only OAuth 2 tokens are used any more and without it, have
    // to case darned enar everywhere to AccessTokenImpl. I.e., this class is now
    // basically AccessTokenImpl thanks to package visibility.
     JSONObject getPayload();
    void setPayload(JSONObject jsonObject);

}
