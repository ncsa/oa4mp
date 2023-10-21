package edu.uiuc.ncsa.oa4mp.delegation.common.token.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import net.sf.json.JSONObject;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Mar 16, 2011 at  1:01:13 PM
 */
public class AccessTokenImpl extends TokenImpl implements AccessToken {
    /**
     * For tokens that are not complex (e.g. not a WLCG token)
     *
     * @param token
     */
    public AccessTokenImpl(URI token) {
        super(token);
    }

    /**
     * @param sciToken an opaque string that is the encoded complex token.
     * @param jti      the unique id for the token. Used to get lifetime etc.
     */
    public AccessTokenImpl(String sciToken, URI jti) {
        super(sciToken, jti);
    }

    public AccessTokenImpl() {
        super();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj != null && !(obj instanceof AccessTokenImpl)) return false;
        return super.equals(obj);
    }

    @Override
    protected String getTokenType() {
        return "access_token";
    }

}
