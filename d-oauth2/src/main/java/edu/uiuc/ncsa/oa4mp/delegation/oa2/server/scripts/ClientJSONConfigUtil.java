package edu.uiuc.ncsa.oa4mp.delegation.oa2.server.scripts;

import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

/**
 * This will read the configuration. It is meant to be used by the {@link ClientScriptsFactory} and
 * its subclasses.
 * to modularize operations on the JSON. Note that the "thingy" refers to a JSON idiom, often used here <i>viz.</i>,
 * a configuration entry of the form {"topLevelKey":JSON} where JSON is either an array or json object.
 * These may be done at any level of the configuration file, so be sure to send in the right JSON object with the topLevelKey.
 * <p/>
 * <p>Created by Jeff Gaynor<br>
 * on 8/30/17 at  3:37 PM
 */
public class ClientJSONConfigUtil {
    public static final String SAVED_KEY = "isSaved";
    public static final String COMMENT_KEY = "comment";
  //  public static final String EXTENDED_ATTRIBUTES = "extended_attributes"; // for attributes that

    /**
     * Return the contents as a JSON array. This also means that if there is a single object, it will
     * be wrapped in a {@link JSONArray}.
     * <pre>
     *  Z=   {"key0":{
     *         "key1':X
     *        }
     *     }
     * </pre>
     * This method returns the JSON array <code>[X]</code>. Another example:
     * <pre>                        OA2Coms
     *  Z=   {"key0":{
     *         "key1':[X,y,z]
     *        }
     *     }
     * </pre>
     * This method returns the JSON array <code>[X,y,z]</code>.
     *
     * @param topLevelKey
     * @param config
     * @param key
     * @return
     */

    public static JSONArray getThingies(String topLevelKey, JSONObject config, String key) {
        if (!config.containsKey(topLevelKey)) {
            return new JSONArray();
        }
        JSONObject claims = config.getJSONObject(topLevelKey);
        Object obj = claims.get(key);
        if (obj instanceof JSONArray) {
            return (JSONArray) obj;
        }
        JSONArray array = new JSONArray();
        array.add(obj);
        return array;
    }

    /**
     * Return the {@link JSONObject} for the given key. This will fail if there is not a single object there,
     * <p/>
     * <pre>
     *  Z=   {"key0":{
     *         "key1':X
     *        }
     *     }
     * </pre>
     * the call <code>getThingy("key0",Z,"key1")</code> returns X.
     *
     * @param topLevelKey
     * @param config
     * @param key
     * @return
     */
    public static JSONObject getThingy(String topLevelKey, JSONObject config, String key) {
        if (!config.containsKey(topLevelKey)) {
            return new JSONObject();
        }
        return config.getJSONObject(topLevelKey);
    }

    /**
     * Sets a JSON object at the given level.
     * <pre>
     *  Z=   {"key0":{
     *         ... stuff...
     *        }
     *     }
     * </pre>
     * The call <code>setThingy("key0:,Z,"key1",X)</code> results in
     * <pre>
     *  Z=   {"key0":{
     *         "key1':X,
     *          ... stuff ...
     *        }
     *     }
     * </pre>
     * This may involve replacing the value of key1 with X if there is already a value there.
     *
     * @param topLevelKey
     * @param config
     * @param key
     * @param thingy
     */
    public static void setThingy(String topLevelKey, JSONObject config, String key, JSON thingy) {
        JSONObject claims;
        if (config.containsKey(topLevelKey)) {
            claims = config.getJSONObject(topLevelKey);
        } else {
            claims = new JSONObject();
        }
        claims.put(key, thingy);
        config.put(topLevelKey, claims);

    }

    /**
     * Drills down a level to check if this thingy has the given object. So if you have the following
     * <pre>
     *  Z=   {"key0":{
     *         "key1':X
     *        }
     *     }
     * </pre>
     * The call here would be <code>hasThingy("key0",Z,"key1');</code> that would return <code>true</code>
     *
     * @param topLevelKey
     * @param key
     * @param config
     * @return
     */
    public static boolean hasThingy(String topLevelKey, String key, JSONObject config) {
        JSONObject claims;
        if (config.containsKey(topLevelKey)) {
            claims = config.getJSONObject(topLevelKey);
        } else {
            return false;
        }
        return claims.containsKey(key);
    }


    /**
     * Checks if the argument has a comment flag.
     *
     * @param config
     * @return
     */
    public static JSONArray getComment(JSONObject config) {
        if (!config.containsKey(COMMENT_KEY)) {
            return new JSONArray();
        }
        try {
            return config.getJSONArray(COMMENT_KEY);
        } catch (JSONException jsx) {
            // means that the entry is not a JSON Array, so process it generically
            // and return it folded in to one.
            JSONArray array = new JSONArray();
            array.add(config.getString(COMMENT_KEY));
            return array;
        }

    }

    public static void setComment(JSONObject config, JSONArray comment) {
        config.put(COMMENT_KEY, comment);
    }

    public static void setComment(JSONObject config, String comment) {
        JSONArray array = new JSONArray();
        array.add(comment);
        config.put(COMMENT_KEY, array);
    }
    
}
