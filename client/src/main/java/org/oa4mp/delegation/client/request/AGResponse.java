package org.oa4mp.delegation.client.request;


import org.oa4mp.delegation.common.token.AuthorizationGrant;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  3:38:49 PM
 */
public class AGResponse extends BasicResponse {
    public AGResponse(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    AuthorizationGrant authorizationGrant;
}
