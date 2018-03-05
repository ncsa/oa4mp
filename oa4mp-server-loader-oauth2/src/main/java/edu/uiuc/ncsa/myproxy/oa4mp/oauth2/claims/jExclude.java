package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.HashMap;
import java.util.HashSet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:50 PM
 */
public class jExclude extends ClaimFunctor {
    public jExclude(HashMap<String, String> claims) {
        super("$exclude", claims);
    }

    @Override
    public Object execute() {
        HashSet<String> newClaims = new HashSet<>();
        for (int i = 0; i < getArgs().size(); i++) {
            Object obj = getArgs().get(i);

            String newClaim = null;
            if (obj instanceof JFunctor) {
                JFunctor ff = (JFunctor) obj;
                ff.execute();
                newClaim = String.valueOf(ff.getResult());
            } else {
                newClaim = String.valueOf(obj);
            }
            if (newClaim != null) {
                newClaims.add(newClaim);
            }

        }
        for (String claim : newClaims) {
            claims.remove(claim);
        }
        result = null;
        return result;
    }
}
