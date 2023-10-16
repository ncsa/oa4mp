package edu.uiuc.ncsa.oa4mp.delegation.common.token.impl;

import java.net.URI;

/**
 * This is used for ID tokens. Note that this is mostly used in the exchange endpoint
 * because of the signature of Java methods. At some point it should probably
 * get used more widely.
 * <p>Created by Jeff Gaynor<br>
 * on 10/13/23 at  6:24 AM
 */
public class IDTokenImpl extends TokenImpl{
    public IDTokenImpl(String sciToken, URI jti) {
        super(sciToken, jti);
    }

    public IDTokenImpl(URI token) {
        super(token);
    }
}
