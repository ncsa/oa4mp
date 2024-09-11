package org.oa4mp.delegation.common.storage;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * Budding collection of useful tools for creating complex JSON objects.
 * <p>
 *     The structure of a JSON serialization is {name:{key0:val0,...}} where name is the name of the component
 * e.g. client, admin, ldap,... etc. So this lets you create a JSON object that has a single JSON object
 * as its value and directly do set/get against the value object. </p>
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  2:12 PM
 */
public class JSONUtil {
    public JSONUtil(String componentName) {
        this.componentName = componentName;
    }

    public String getComponentName() {
        return componentName;
    }

    String componentName;

    /*

This method sets or gets one of the components from the JSON object
 */
    public Object getJSONValue(JSONObject json, String key) {
        if (!hasKey(json, key)) return null;
        return json.getJSONObject(getComponentName()).get(key);
    }

    public JSONArray getJSONArray(JSONObject json, String key) {
        if (!hasKey(json, key)) return null;
        Object object = getJSONValue(json, key);
        JSONArray array = JSONArray.fromObject(object); // should get converted from a String
        return array;
    }

    public String getJSONValueString(JSONObject json, String key) {
        if (!hasKey(json, key)) return null;
        Object object = getJSONValue(json, key);

        if (object == null) return null;
        return object.toString();
    }

    public boolean hasKey(JSONObject json, String key) {
        return json.getJSONObject(getComponentName()).containsKey(key);
    }

    /**
     * get a boolean value. Returns <code>false</code> if no such value.
     * @param json
     * @param key
     * @return
     */
    public boolean getJSONValueBoolean(JSONObject json, String key) {
        if (!hasKey(json, key)) return false;
        return json.getJSONObject(getComponentName()).getBoolean(key);
    }

    public long getJSONValueLong(JSONObject json, String key) {
        if (!hasKey(json, key)) return 0;

        return json.getJSONObject(getComponentName()).getLong(key);
    }

    public int getJSONValueInt(JSONObject json, String key) {
        if (!hasKey(json, key)) return 0;
        return json.getJSONObject(getComponentName()).getInt(key);
    }

    public void setJSONValue(JSONObject json, String key, Object value) {
        if (value == null) return;
        json.getJSONObject(getComponentName()).put(key, value);
    }
}
