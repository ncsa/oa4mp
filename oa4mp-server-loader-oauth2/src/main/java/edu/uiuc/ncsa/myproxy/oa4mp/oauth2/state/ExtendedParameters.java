package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/18/20 at  7:14 AM
 */
public class ExtendedParameters {
    public static String CILOGON_NS = "cilogon";
    public static String OA4MP_NS = "oa4mp";
    public static String PREFIX_DELIMITER = ":";
    public static String EXTENDED_ATTRIBUTES_KEY = "extendedAttributes";
    public static String[] NS_LIST = new String[]{CILOGON_NS, OA4MP_NS};

    /**
     * This will take a raw parameter from a servlet of the form
     * <br/><br/>
     * NS:attr=val1,val2,val3,...
     * <br/><br/>
     * and turn it in to a JSON object of the form
     * <br/><br/>
     * {"NS":{"attr":[val1,val2,val3,...]}}
     * <br/><br/>
     * These are then stored in the transaction if the client has extended attribute support allowed. Note
     * that if there is no such parameter, then this return null;
     *
     * @param rawKey
     * @param rawValues
     * @return
     */
    public JSONObject toJSON(String rawKey, String[] rawValues) {
        String ns = rawKey.substring(0,rawKey.indexOf(PREFIX_DELIMITER));
        if (ns.isEmpty()) {
            return null;
        }

        if (!isInNamespace(ns)) return null; // don't recognize the namespace for this.
        JSONObject output = new JSONObject();
        String key = rawKey.substring(rawKey.indexOf(PREFIX_DELIMITER) + 1);
        if ((rawValues == null || rawValues.length == 0) && key.isEmpty()) {
            return null;  // fine. They didn't send anything of interest.
        }

        if (key.isEmpty()) {
            throw new IllegalArgumentException("Error: There was no key key associated with the parameter \"" + rawKey + "\"");
        }
        // checks done, now we can pull this apart.
        JSONObject entry = new JSONObject();
        JSONArray array = new JSONArray();
        array.addAll(Arrays.asList(rawValues));
        entry.put(key, array);
        output.put(ns, entry);
        return output;
    }

    public boolean isInNamespace(String x) {
        for (String n : NS_LIST) {
            if (n.equals(x)) return true;
        }
        return false;
    }

    /**
     * This does the grunt work of looking through the headers and pulling out the extended attributes.
     * The format of the extended attributes is
     * <pre>
     * {"extendedAttributes":[
     *     {"NS0":[
     *        {"key0_0":[values]},
     *        {"key0_1":[values]},...
     *        ]
     *     },
     *     {"NS1":[
     *         {"key1_0":[values]},
     *         {"key1_1":[values]},...
     *         ]
     *      },
     *   ]
     * }
     * </pre>
     * where
     * <ul>
     *     <li>NS is one of the approved namespaces for this client, e.g. oa4mp</li>
     *     <li>The key is of the form NS:key and there may be several keys. There may be arbitrarily many</li>
     *     <li>The values of each key is assumed to be a string array.</li>
     * </ul>
     *
     * @param pmap -- map of parameters from e.g. a servlet request
     * @return
     */
    public JSONObject snoopHeaders(Map<String, String[]> pmap) {
        JSONArray cilogonArray = null;
        JSONArray oa4mpArray = null;
        JSONArray thisArray = null;
        for (String key : pmap.keySet()) {
            String[] values = pmap.get(key);
            JSONObject j = toJSON(key, values);
            if (j != null) {
                if (j.containsKey(CILOGON_NS)) {
                    if (cilogonArray == null) {
                        cilogonArray = new JSONArray();
                    }
                    cilogonArray.add(j.getJSONObject(CILOGON_NS));
                }
                if (j.containsKey(OA4MP_NS)) {
                    if (oa4mpArray == null) {
                        oa4mpArray = new JSONArray();
                    }
                    oa4mpArray.add(j.getJSONObject(OA4MP_NS));
                }
            }
        }
        JSONArray entry = new JSONArray();
        if (cilogonArray != null && !cilogonArray.isEmpty()) {
            JSONObject centry = new JSONObject();
            centry.put(CILOGON_NS, cilogonArray);
            entry.add(centry);
        }
        if (oa4mpArray != null && !oa4mpArray.isEmpty()) {
            JSONObject oentry = new JSONObject();
            oentry.put(OA4MP_NS, oa4mpArray);
            entry.add(oentry);
        }
        JSONObject output = new JSONObject();

        if (entry.isEmpty()) {
            return output;
        }
        output.put(EXTENDED_ATTRIBUTES_KEY, entry);
        return output;

    }
    public static void main(String[] args){
        HashMap<String, String[]> pmap = new HashMap<>();
        pmap.put(CILOGON_NS + ":role", new String[]{"a","b"});
        pmap.put(CILOGON_NS + ":role2", new String[]{"c","d"});
        pmap.put(CILOGON_NS + ":role3", new String[]{"e"});
        pmap.put(OA4MP_NS + ":role1", new String[]{"A", "B", "C"});
        pmap.put(OA4MP_NS + ":foo", new String[]{"D", "E", "F"});
        ExtendedParameters xp = new ExtendedParameters();
        System.out.println(xp.snoopHeaders(pmap).toString(2));
    }
}
