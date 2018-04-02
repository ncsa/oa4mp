package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.FunctorType;
import edu.uiuc.ncsa.security.util.functor.JFunctorImpl;

import java.util.HashMap;
import java.util.Map;

/**
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
