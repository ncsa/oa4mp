package edu.uiuc.ncsa.oa4mp.delegation.common.token.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.OA1TokenImpl;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/9/20 at  10:11 AM
 */
public class OA1AuthorizationGrantImpl extends OA1TokenImpl implements AuthorizationGrant {
    public OA1AuthorizationGrantImpl(URI token, URI sharedSecret) {
        super(token, sharedSecret);
    }
}
