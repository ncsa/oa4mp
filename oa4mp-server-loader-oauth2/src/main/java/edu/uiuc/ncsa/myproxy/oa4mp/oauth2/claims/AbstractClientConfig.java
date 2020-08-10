package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine;
import edu.uiuc.ncsa.qdl.scripting.AnotherJSONUtil;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSONObject;

/**
 * This corresponds to the client's configuration for its various tokens (the "cfg" attribute).
 * These are typically returned by the client, e.g. {@link OA2Client#getIDTokenConfig()},
 * {@link OA2Client#getSciTokensConfig()}. Note that this si nto designed to be terribly dynamic.
 * It reads the configuration and returns information about it.
 * <p>Created by Jeff Gaynor<br>
 * on 7/1/20 at  2:45 PM
 */
public abstract class AbstractClientConfig {

    public void fromJSON(JSONObject jsonObject){
        if(jsonObject.containsKey(QDLRuntimeEngine.CONFIG_TAG)) {
            setScriptSet(AnotherJSONUtil.createScripts(jsonObject.getJSONObject(QDLRuntimeEngine.CONFIG_TAG)));
        }
    }
    public  JSONObject toJSON(){
        JSONObject c = new JSONObject();
      /*  if(!getScriptSet().isEmpty()){
            //c.put("qdl":)
        }*/
        return c;
    }
    public  ScriptSet getScriptSet(){
        if(scriptSet == null){
            scriptSet = new ScriptSet();
        }
        return scriptSet;
    }
    ScriptSet scriptSet;
    public void setScriptSet(ScriptSet scriptSet){
        this.scriptSet = scriptSet;
    }
}
