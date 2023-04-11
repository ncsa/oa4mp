package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows;

import edu.uiuc.ncsa.security.util.functor.FunctorType;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.JFunctorImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/18 at  1:10 PM
 */
public abstract class FlowFunctor extends JFunctorImpl {
    public FlowFunctor(FunctorType type) {
        super(type);
    }

    @Override
    public Object execute() {
        if(!isExecuted()){
            checkArgs(); // should be exactly one argument
           Object obj =  getArgs().get(0);
            if(obj instanceof JFunctor){
                result = ((JFunctor)obj).execute();
                executed = true;
            }

        }
        return result;
    }
}
