package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATResponse;
import org.oa4mp.delegation.common.token.Verifier;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * OIDC server response for request for access token
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:10 PM
 */
public class ATIResponse2 extends IDTokenResponse implements ATResponse {
    public ATIResponse2(AccessTokenImpl accessToken,
                        RefreshTokenImpl refreshToken,
                        boolean isOIDC) {
        super(accessToken,refreshToken,isOIDC);
    }
    Verifier verifier;

    /**
     * Getter for verifier
     * This shouldn't be called in OIDC, but it's here temporarily
     *
     * @return verifier (should be null)
     */
    public Verifier getVerifier() {
        return verifier;
    }


    /**
     * Setter for verifier
     * This needs to go away since OIDC doesn't use verifiers
     *
     * @param verifier Verifier object (probably null)
     */
    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }

}
