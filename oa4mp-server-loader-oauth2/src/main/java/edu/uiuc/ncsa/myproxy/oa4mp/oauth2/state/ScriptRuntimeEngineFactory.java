package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.FunctorRuntimeEngine;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  1:36 PM
 */
public class ScriptRuntimeEngineFactory {
    public static ScriptRuntimeEngine createRTE(OA2SE oa2SE, OA2ServiceTransaction transaction, JSONObject config){
        // note: No QDL tag means no scripting for QDL even if there is an environment configured.
        // This is because there is nothing to execute so no reason to incur the overhead of creating it.
        if(config.containsKey(OA2ClientFunctorScriptsUtil.CLAIMS_KEY)){
            return new FunctorRuntimeEngine(config);
        }

            if(oa2SE.getQDLEnvironment() == null || !oa2SE.getQDLEnvironment().isEnabled()){
                oa2SE.getMyLogger().warn("**********************************");
                oa2SE.getMyLogger().warn("QDL scripting detected, but no QDL runtime engine has been configured.");
                oa2SE.getMyLogger().warn("No QDL scripts will be run.");
                oa2SE.getMyLogger().warn("**********************************");
            }else {
                QDLRuntimeEngine qrt =  new QDLRuntimeEngine(oa2SE.getQDLEnvironment());
                OA2State state = qrt.getState();
                state.setOa2se(oa2SE);
                state.setTransaction(transaction);

                return qrt;
            }
        return null;
    }


    public static class NoOpRuntimeEngine extends ScriptRuntimeEngine{
        public NoOpRuntimeEngine() {
            
        }

        @Override
        public String serializeState() {
            return "";
        }

        @Override
        public void deserializeState(String state) {

        }
        // we need exactly one of these.
        public final static ScriptRunResponse srr = new ScriptRunResponse(null, null, ScriptRunResponse.RC_NOT_RUN);
        @Override
        public ScriptRunResponse run(ScriptRunRequest request) {
            return srr;
        }
    }
}
