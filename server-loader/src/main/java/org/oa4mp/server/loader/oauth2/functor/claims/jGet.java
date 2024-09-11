package org.oa4mp.server.loader.oauth2.functor.claims;

import java.util.Map;

/**
 * This returns the value of the claim.
 * <pre>
 *     $get[claim]
 * </pre>
 * The value will be the empty string if the claim does not exist (rather than a null). E.g.
 * <pre>
 *     $get["eppn"]
 * </pre>
 * might return a value of "bob@bigstate.edu".
 * <p>Created by Jeff Gaynor<br>
 * on 6/14/18 at  9:03 AM
 */
public class jGet extends ClaimFunctor {
    public jGet( Map<String, Object> claims) {
        super(FunctorClaimsType.GET, claims);
    }

    @Override
    public Object execute() {
        if(executed){
            return result;
        }
        if(claims == null ||
                getArgs().size() == 0 || // no args
                getArgs().get(0) == null || //the elements are null;
                !claims.containsKey(getArgs().get(0))){
            result = "";
            executed = true;
            return "";
        }

        result =  claims.get(getArgs().get(0));
        if(result == null){
            result = "";
        }
        executed = true;
        return result;
    }
}
