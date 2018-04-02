package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType.INCLUDE;

/**
 * This will include only the list of claims in the final claims object.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:11 PM
 */
public class jInclude extends ClaimFunctor {
    public jInclude(Map<String, Object> claims) {
        super(INCLUDE, claims);
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
        Set<String> currentClaims = new HashSet<>();
        // copy the values over or you will get a conurrent modification exception later
        // when you try to remove values.
        for(String x : claims.keySet()){
            currentClaims.add(x);
        }

        for (String claim : currentClaims) {
            if (!newClaims.contains(claim)) {

                claims.remove(claim);
            }
        }
        result = null;
        return result;
    }
}
