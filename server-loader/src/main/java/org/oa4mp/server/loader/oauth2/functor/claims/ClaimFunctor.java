package org.oa4mp.server.loader.oauth2.functor.claims;

import edu.uiuc.ncsa.security.util.functor.FunctorType;
import edu.uiuc.ncsa.security.util.functor.JFunctorImpl;

import java.util.HashMap;
import java.util.Map;

/**
 * A functor that operates on claims. Note that the contract is that if there are
 * no claims to operate on, then nothng is done , i.e. there is no execution.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:03 PM
 */
public abstract class ClaimFunctor extends JFunctorImpl {
    public Map<String, Object> getClaims() {
        return claims;
    }

    public void setClaims(HashMap<String, Object> claims) {
        this.claims = claims;
    }

    protected Map<String, Object> claims;

    protected ClaimFunctor(FunctorType type, Map<String, Object> claims) {
        super(type);
        this.claims = claims;
    }
}
