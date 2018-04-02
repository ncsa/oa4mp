package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows;

import edu.uiuc.ncsa.security.util.functor.FunctorType;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/18 at  1:08 PM
 */
public class jGetClaims extends FlowFunctor {
    public jGetClaims(FunctorType type) {
        super(FlowType.GET_CLAIMS);
    }

}
