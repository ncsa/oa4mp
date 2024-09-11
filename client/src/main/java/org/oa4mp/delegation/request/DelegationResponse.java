package org.oa4mp.delegation.request;


import org.oa4mp.delegation.common.token.AuthorizationGrant;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 14, 2011 at  3:42:00 PM
 */
public class DelegationResponse extends BasicResponse {
    public DelegationResponse(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    AuthorizationGrant authorizationGrant;

    public URI getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(URI redirectUri) {
        this.redirectUri = redirectUri;
    }

    URI redirectUri;
}
