package org.oa4mp.server.loader.oauth2.functor.claims;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

import java.util.Map;

/**
 * This will rename a claim. <br/><br/>
 * <pre>
 *    $rename[source, target]
 * </pre>
 * If the claim is named "source" it will be renamed to "target", e.g. $rename["member_of", "isMemberOf"].
 * The result of this will be true if the claim was renamed and false otherwise (e.g. if the given claim fails to exist.)
 * <p>Created by Jeff Gaynor<br>
 * on 7/12/18 at  3:49 PM
 */
public class jRename extends ClaimFunctor {
    public jRename(Map<String, Object> claims) {
        super(FunctorClaimsType.RENAME, claims);
    }

    @Override
    public Object execute() {
        if(getArgs().size() != 2){
            throw new GeneralException("Error: the rename functor requires two arguments");
        }
        if(isExecuted()){
            return result;
        }
        String oldName = String.valueOf(getArgs().get(0));
        if(getClaims().containsKey(oldName)) {
            String newName = String.valueOf(getArgs().get(1));

            getClaims().put(newName, getClaims().get(oldName));
            getClaims().remove(oldName);
            result = true;
        }else{
            result = false;
        }
        executed = true;

        return result;
    }
}
