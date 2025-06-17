package org.oa4mp.delegation.client.request;


import org.oa4mp.delegation.common.token.AuthorizationGrant;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 12, 2011 at  1:05:23 PM
 */
public class CallbackResponse extends BasicResponse {
    AuthorizationGrant authorizationGrant;

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

}
