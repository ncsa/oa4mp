package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.HashSet;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType.EXCLUDE;

/**
  * This will omit the claims. You may give any list of claim names (rather than values) you wish. If
  * a claim is not present, then nothing is done, i.e., the contract is to ensure that the stated claims
  * are not returned so there is no error if the claim fails to exist in the first place.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:50 PM
 */
public class jExclude extends ClaimFunctor {
    public jExclude(Map<String, Object> claims) {
        super(EXCLUDE, claims);
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
