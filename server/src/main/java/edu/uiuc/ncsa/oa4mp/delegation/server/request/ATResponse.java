package edu.uiuc.ncsa.oa4mp.delegation.server.request;

import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.Verifier;

/**
 * Server response to a request for an {@link AccessToken}
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  12:35:57 PM
 */
public interface ATResponse extends IssuerResponse {
    public AccessToken getAccessToken();

    public Verifier getVerifier();
}
