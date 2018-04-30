package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows;

import edu.uiuc.ncsa.security.util.functor.JFunctorImpl;

/**
 * This sets the claim source. The syntax is
 *    <pre>{"$set_claim_source":[alias, cfg_name]}</pre>
 *  Where
 *  <ul>
 *      <li>alias=the alias of the class name. Thsi is a claim source that will be instantiated</li>
 *      <li>cfg_name = the name of the configuration specified in the claims sources. </li>
 *  </ul>
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/18 at  4:03 PM
 */
public class jSetClaimSource extends JFunctorImpl {
    public jSetClaimSource() {
        super(FlowType.SET_CLAIM_SOURCE);
    }


    @Override
    public Object execute() {
        executed = true;
        return null;
    }
}
