package edu.uiuc.ncsa.oa4mp.delegation.client.request;


import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  4:03:05 PM
 */
public class ATResponse extends BasicResponse {
    public ATResponse(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    AccessToken accessToken;

}
