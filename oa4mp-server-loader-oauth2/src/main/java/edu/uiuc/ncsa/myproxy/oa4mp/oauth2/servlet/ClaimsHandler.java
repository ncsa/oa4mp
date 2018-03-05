package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.util.functor.LogicBlock;

import java.util.Map;

/**
 * After the claims have been created, processing can be applied to them as per configuration.
 * <p>Created by Jeff Gaynor<br>
 * on 3/2/18 at  3:12 PM
 */

public class ClaimsHandler {

    LogicBlock logicBlock;
    public Map<String,Object> process(Map<String,Object> claims){
        logicBlock.execute();
        return claims;
    }
}
