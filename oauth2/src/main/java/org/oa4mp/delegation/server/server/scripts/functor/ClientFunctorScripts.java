package org.oa4mp.delegation.server.server.scripts.functor;

import org.oa4mp.delegation.server.server.scripts.ClientScripts;
import edu.uiuc.ncsa.security.util.functor.parser.FunctorScript;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/5/20 at  2:15 PM
 */
public class ClientFunctorScripts<V extends FunctorScript> extends ScriptSet<V> implements ClientScripts {
    public void setRuntime(FunctorScript runtime) {
           this.runtime = runtime;
       }

       public FunctorScript getRuntime(){
           return runtime;
       }

       /**
        * Executes the runtime. This returns true if there is  a runtime and it is executed, false otherwise.
        * @return
        */
       public boolean executeRuntime(){
           if(runtime!= null){
               runtime.execute();
               return true;
           }
           return false;
       }
    FunctorScript runtime;
}
