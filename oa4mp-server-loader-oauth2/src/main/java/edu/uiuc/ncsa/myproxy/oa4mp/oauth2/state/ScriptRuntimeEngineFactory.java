package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.FunctorRuntimeEngine;
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
    public static ScriptRuntimeEngine createRTE(JSONObject config){
        if(config.containsKey(QDLRuntimeEngine.CONFIG_TAG)){
            return new QDLRuntimeEngine(config.getJSONObject(QDLRuntimeEngine.CONFIG_TAG));
        }
        if(config.containsKey("config")){
            return new FunctorRuntimeEngine(config);
        }
        return new NoOpRuntimeEngine(null);
    }


    public static class NoOpRuntimeEngine extends ScriptRuntimeEngine{
        public NoOpRuntimeEngine(JSONObject config) {
            super(config);
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
