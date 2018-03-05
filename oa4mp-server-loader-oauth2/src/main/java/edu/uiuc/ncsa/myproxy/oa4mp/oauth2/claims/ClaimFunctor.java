package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctorImpl;

import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:03 PM
 */
public abstract class ClaimFunctor extends JFunctorImpl {
    public HashMap<String, String> getClaims() {
        return claims;
    }

    public void setClaims(HashMap<String, String> claims) {
        this.claims = claims;
    }

    protected HashMap<String,String> claims;

    protected ClaimFunctor(String name, HashMap<String,String> claims) {
        super(name);
        this.claims = claims;
    }

}
