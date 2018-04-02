package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType.SET;

/**
 * Sets a claim to a specified value.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:03 PM
 */
public class jSet extends ClaimFunctor {
    public jSet(Map<String,Object> claims) {
        super(SET, claims);
    }

    @Override
    public Object execute() {
        String claim = String.valueOf(getArgs().get(0));
        if(!claims.containsKey(claim)){
            return null;
        }
        Object obj = getArgs().get(1);
        String newValue = null;
        if(obj instanceof JFunctor){
            JFunctor ff = (JFunctor)obj;
            ff.execute();
            newValue =String.valueOf(ff.getResult());
        }else{
           newValue = String.valueOf(obj);
        }
        claims.put(claim, newValue);
        return newValue;
    }
}
