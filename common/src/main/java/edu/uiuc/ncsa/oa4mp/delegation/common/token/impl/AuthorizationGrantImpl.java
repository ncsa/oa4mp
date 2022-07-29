package edu.uiuc.ncsa.oa4mp.delegation.common.token.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;

import java.net.URI;

/**
 * The OAuth 1.0a version of an AuthorizationGrant
 * <p>Created by Jeff Gaynor<br>
 * on Mar 16, 2011 at  1:00:30 PM
 */
public class AuthorizationGrantImpl extends TokenImpl implements AuthorizationGrant {
    public AuthorizationGrantImpl(URI token) {
        super(token);
    }

    public AuthorizationGrantImpl(String sciToken, URI jti) {
        super(sciToken, jti);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthorizationGrantImpl)) {
            return false;
        }
        return super.equals(obj);
    }
}
