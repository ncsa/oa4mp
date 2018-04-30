package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctor;

import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType.SET;

/**
 * Sets a claim to a specified value. Note that this will <b>create</b> a claim if none exists.
 * That claim will then be returned. If you do not want to return it, you should invoke the
 * $remove functor on it. Note that if there are no claims, then they cannot be set and
 * nothing happens.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  12:03 PM
 */
public class jSet extends ClaimFunctor {
    public jSet(Map<String,Object> claims) {
        super(SET, claims);
    }

    @Override
    public Object execute() {
        if(claims == null){
            return null;
        }
        String claim = String.valueOf(getArgs().get(0));
        Object obj = getArgs().get(1);
        String newValue = null;
        if(obj instanceof JFunctor){
            JFunctor ff = (JFunctor)obj;
            ff.execute();
            newValue =String.valueOf(ff.getResult());
        }else{
           newValue = String.valueOf(obj);
        }
        if(claims!=null) {
            claims.put(claim, newValue);
        }
        executed = true;
        return newValue;
    }
}
