package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine;
import edu.uiuc.ncsa.qdl.scripting.AnotherJSONUtil;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSON;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * This corresponds to the client's configuration for its various payloads -- tokens in this case.
 * These are typically returned by the client, e.g. {@link OA2Client#getIDTokenConfig()},
 * {@link OA2Client#getAccessTokensConfig()} . Note that this is not designed to be terribly dynamic.
 * It reads the configuration and returns information about it. To update a configuration, you need to
 * twiddle the configuration itself.
 * <p>Created by Jeff Gaynor<br>
 * on 7/1/20 at  2:45 PM
 */
public abstract class AbstractPayloadConfig implements Serializable {
    public static String TYPE_KEY = "type";
    public static String ID_KEY = "id";
    public static String VERSIONS_KEY = "versions";
    public static String CREATE_TS_KEY = "creation_ts";
    public static String LIFETIME_KEY = "lifetime";

    protected String type = null;
    List<String> versions;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Date getCreationTS() {
        if(creationTS == null){
            creationTS = new Date();
        }
        return creationTS;
    }

    public void setCreationTS(Date creationTS) {
        this.creationTS = creationTS;
    }

    String id;
    Date creationTS;
    JSON rawScripts = null;

    public void fromJSON(JSONObject jsonObject) {
        if (jsonObject.containsKey(LIFETIME_KEY)) {
            Object rawLifetime = jsonObject.get(LIFETIME_KEY);
            if(rawLifetime instanceof String){
                lifetime = XMLConfigUtil.getValueSecsOrMillis((String)rawLifetime, false);
            }else {
                // assume it is a long and let JSON figure it out
                lifetime = jsonObject.getLong(LIFETIME_KEY);
            }
        }
        if(jsonObject.containsKey(QDLRuntimeEngine.CONFIG_TAG)) {
            try{
                rawScripts = jsonObject.getJSONObject(QDLRuntimeEngine.CONFIG_TAG);
            }catch (JSONException jsonException){
                rawScripts = jsonObject.getJSONArray(QDLRuntimeEngine.CONFIG_TAG);
            }
            //rawScripts = jsonObject.getJSONObject(QDLRuntimeEngine.CONFIG_TAG);
            if(rawScripts == null){
                throw new IllegalArgumentException("error: no recognizable scripts found for \"" + jsonObject.getString(QDLRuntimeEngine.CONFIG_TAG) + "\"");
            }
            setScriptSet(AnotherJSONUtil.createScripts(rawScripts));
        }
        if (jsonObject.containsKey(TYPE_KEY)) {
            type = jsonObject.getString(TYPE_KEY);
        } else {
            throw new IllegalStateException("Error: Missing type for access token handler configuration");
        }
        if (jsonObject.containsKey(VERSIONS_KEY)) {
            versions = jsonObject.getJSONArray(VERSIONS_KEY);
        }
        if(jsonObject.containsKey(ID_KEY)){
            id = jsonObject.getString(ID_KEY);
        }
        if(jsonObject.containsKey(CREATE_TS_KEY)){
            try {
                Calendar calendar = Iso8601.string2Date(jsonObject.getString(CREATE_TS_KEY));
                creationTS = calendar.getTime();
            }catch( ParseException pe){
                creationTS = new Date(); // set to now.
            }
        }
    }
    public  JSONObject toJSON(){
        JSONObject json = new JSONObject();
        if (type != null) {
            json.put(TYPE_KEY, type);

        }
        if (lifetime != null) {
             json.put(LIFETIME_KEY, lifetime);
         }
        if (versions != null) {
            json.put(VERSIONS_KEY, versions);
        }
        if(!StringUtils.isTrivial(id)){
            json.put(ID_KEY, id);
        }
        json.put(CREATE_TS_KEY, Iso8601.date2String(getCreationTS()));
        json.put(QDLRuntimeEngine.CONFIG_TAG, rawScripts);
        return json;
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

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<String> getVersions() {
        return versions;
    }

    public void setVersions(List<String> versions) {
        this.versions = versions;
    }
        Long lifetime = -1L;

    public Long getLifetime() {
        return lifetime;
    }

    public void setLifetime(Long lifetime) {
        this.lifetime = lifetime;
    }

}
