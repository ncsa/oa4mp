package edu.uiuc.ncsa.oa4mp.delegation.common.token.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/2/13 at  12:02 PM
 */
public class RefreshTokenImpl extends TokenImpl implements RefreshToken {
    public RefreshTokenImpl(URI token) {
        super(token);
    }

    public RefreshTokenImpl(String sciToken, URI jti) {
        super(sciToken, jti);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj
                instanceof
                RefreshTokenImpl)) {
            return false;
        }
        return super.equals(obj);
    }
}
