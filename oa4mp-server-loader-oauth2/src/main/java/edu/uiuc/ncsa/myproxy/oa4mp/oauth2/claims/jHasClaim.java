package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.Map;

/**
 * This takes the name of a claim and returns whether or not it exists in the current set of claims.
 * <pre>
 *     $jHasClaim[X]
 * </pre>
 * returns true if X is a claim. False otherwise. For instance, to check if the eppn claim has been set
 * <pre>
 *     $jHasClaim["eppn"]
 * </pre>
 * Note that you do <b>not</b> supply the value of the claim, just its name (which may be computed by another functor,
 * of course).
 * <p/>
 * <p>Created by Jeff Gaynor<br>
 * on 6/13/18 at  6:13 PM
 */
public class jHasClaim extends ClaimFunctor {
    public jHasClaim(Map<String, Object> claims) {
        super(FunctorClaimsType.HAS_CLAIM, claims);
    }

    @Override
    public Object execute() {
        if (claims == null || getArgs().size() == 0) {
            return false;
        }
        Object obj = getArgs().get(0);

        String newValue = null;
        if (obj instanceof JFunctor) {
            JFunctor ff = (JFunctor) obj;
            ff.execute();
            newValue = String.valueOf(ff.getResult());
        } else {
            newValue = String.valueOf(obj);
        }
        result = claims.containsKey(newValue);
        executed = true;
        return result;
    }
}
