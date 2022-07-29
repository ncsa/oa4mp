package edu.uiuc.ncsa.oa4mp.delegation.client.request;


import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 12, 2011 at  1:05:23 PM
 */
public class CallbackResponse extends BasicResponse {
    AuthorizationGrant authorizationGrant;
    Verifier verifier;

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    public Verifier getVerifier() {
        return verifier;
    }

    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }
}
