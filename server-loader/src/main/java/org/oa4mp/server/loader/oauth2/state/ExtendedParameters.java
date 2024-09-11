package org.oa4mp.server.loader.oauth2.state;

import org.qdl_lang.variables.QDLStem;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/18/20 at  7:14 AM
 */
public class ExtendedParameters {
    public static String CILOGON_NS = "org.cilogon";
    public static String OA4MP_NS = "org.oa4mp";
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
        String ns = rawKey.substring(0, rawKey.indexOf(PREFIX_DELIMITER));
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

    protected boolean isExtendedAttribute(String x) {
        return 0 < x.indexOf(PREFIX_DELIMITER);
    }

    /**
     * This does the grunt work of looking through parameters and pulling out the extended attributes.
     * The basic format of an entry is
     * <pre>
     *     NS:/path=value0[,value1,...]
     * </pre>
     *
     * These parse into the extended attributes as
     * <pre>
     *     {"NS0":
     *        {"key0_0":[values],
     *        "key0_1":[values],...
     *        },
     *     "NS1":
     *         {"key1_0":[values],
     *         "key1_1":[values],...
     *         },
     *      ... more entries
     *   }
     * </pre>
     * where
     * <ul>
     *     <li>NS is one of the approved namespaces for this client, e.g. oa4mp</li>
     *     <li>The key is of the form NS:key and there may be several keys. There may be arbitrarily many</li>
     *     <li>The values of each key is assumed to be a string array.</li>
     * </ul>
     * For example
     * <pre>
     *     cilogon:roles/access=a,b --> {"cilogon":{"roles/access":["a","b"]}}
     * </pre>
     *
     * @param pmap -- map of parameters from e.g. a servlet request
     * @return
     */
    public JSONObject snoopParameters(Map<String, String[]> pmap) {
        if(pmap instanceof JSONObject){
            // JSONObject is a type of map, so Java does not allow for a separate function. Have to convert it here...
            pmap = convertToParameterMap((JSONObject) pmap);
        }
        JSONObject cilogonEntry = null;
        JSONObject oa4mpEntry = null;
        for (String key : pmap.keySet()) {
            if (!isExtendedAttribute(key)) {
                continue;
            }
            String[] values = pmap.get(key);
            JSONObject j = toJSON(key, values); // return {NS:{key:[]}}
            if (j != null) {
                if (j.containsKey(CILOGON_NS)) {
                    if (cilogonEntry == null) {
                        cilogonEntry = new JSONObject();
                    }
                    flattenJSON(CILOGON_NS, cilogonEntry, j);
                }
                if (j.containsKey(OA4MP_NS)) {
                    if (oa4mpEntry == null) {
                        oa4mpEntry = new JSONObject();
                    }
                    flattenJSON(OA4MP_NS, oa4mpEntry, j);
                }
            }
        }
        JSONObject entry = new JSONObject();
        if (cilogonEntry != null && !cilogonEntry.isEmpty()) {
            entry.put(CILOGON_NS, cilogonEntry);
        }
        if (oa4mpEntry != null && !oa4mpEntry.isEmpty()) {
            entry.put(OA4MP_NS, oa4mpEntry);
        }

        if (entry.isEmpty()) {
            return new JSONObject();
        }
        return entry;
    }
    protected Map<String, String[]> convertToParameterMap(JSONObject json) {
        Map<String, String[]> pmap = new HashMap<>();// low budget solution is to just convert it.
        for(Object kk : json.keySet()){
            String key = kk.toString(); // poor man's cast...
            if (!isExtendedAttribute(key)) {
                continue;
            }
            Object value = json.get(kk);
            if(value instanceof JSONArray){
                JSONArray array = (JSONArray) value;
                String[] x = new String[array.size()];
                for(int i = 0; i < array.size(); i++){
                    x[i] = array.getString(i);
                }
                pmap.put(key, x);
            }else{
                pmap.put(key, new String[]{value.toString()});
            }
        }
        return pmap;
    }


    protected void flattenJSON(String namespace, JSONObject cilogonEntry, JSONObject j) {
        JSONObject jo = j.getJSONObject(namespace);
        // flatten it to an object
        for (Object kk : jo.keySet()) {
            cilogonEntry.put(kk, jo.get(kk));
        }
    }

    public static void main(String[] args) {
        HashMap<String, String[]> pmap = new HashMap<>();
        pmap.put(CILOGON_NS + ":role", new String[]{"a", "b"});
        pmap.put(CILOGON_NS + ":roles/access", new String[]{"c", "d"});
        pmap.put(CILOGON_NS + ":roles/no_access", new String[]{"e"});
        pmap.put(OA4MP_NS + ":/roles/", new String[]{"A", "B", "C"});
        pmap.put(OA4MP_NS + ":/idt/lifetime", new String[]{"100000000"});
        ExtendedParameters xp = new ExtendedParameters();
        JSONObject jsonObject = xp.snoopParameters(pmap);

        System.out.println(jsonObject.toString(2));
        QDLStem QDLStem = new QDLStem();
        QDLStem.fromJSON(jsonObject);
        System.out.println(QDLStem.toString(2));
        System.out.println("***");
        System.out.println(QDLStem.get(OA4MP_NS));
        System.out.println(QDLStem.getStem(OA4MP_NS).get("/roles/"));
        // Now an integrity check for the existing configuration.
        JSONObject jsonObject2 = (JSONObject) JSONSerializer.toJSON(rawJ);
        JSONObject cmExtra = (JSONObject) JSONSerializer.toJSON(cmextra);

   //     JSONObject cleanConfig = new JSONObject();
//        ClientJSONConfigUtil.setCMExtraAttributes(cleanConfig, cmExtra);
        //ClientJSONConfigUtil.setExtendedAttributes(cleanConfig, xp.);

    }
    static String rawJ = "{\n" +

            " \"config\": \"LSST client configuration, created by Jeff Gaynor 6/19/2018\",\n" +
            " \"claims\":  {\n" +
            "  \"sourceConfig\": [{\"ldap\":   {\n" +
            "   \"preProcessing\": [   {\n" +
            "    \"$if\": [{\"$match\":     [\n" +
            "     \"${idp}\",\n" +
            "     \"https://idp.ncsa.illinois.edu/idp/shibboleth\"\n" +
            "    ]}],\n" +
            "    \"$then\": [{\"$set\":     [\n" +
            "     \"foo\",\n" +
            "     {\"$drop\":      [\n" +
            "      \"@ncsa.illinois.edu\",\n" +
            "      \"${eppn}\"\n" +
            "     ]}\n" +
            "    ]}],\n" +
            "    \"$else\": [{\"$get_claims\": [\"$false\"]}]\n" +
            "   }],\n" +
            "   \"postProcessing\": [   {\n" +
            "    \"$if\": [{\"$match\":     [\n" +
            "     \"${idp}\",\n" +
            "     \"https://idp.ncsa.illinois.edu/idp/shibboleth\"\n" +
            "    ]}],\n" +
            "    \"$then\":     [\n" +
            "     {\"$set\":      [\n" +
            "      \"sub\",\n" +
            "      {\"$get\": [\"eppn\"]}\n" +
            "     ]},\n" +
            "     {\"$exclude\": [\"foo\"]}\n" +
            "    ]\n" +
            "   }],\n" +
            "   \"failOnError\": \"false\",\n" +
            "   \"address\": \"ldap1.ncsa.illinois.edu, ldap2.ncsa.illinois.edu\",\n" +
            "   \"port\": 636,\n" +
            "   \"enabled\": \"true\",\n" +
            "   \"authorizationType\": \"none\",\n" +
            "   \"searchName\": \"foo\",\n" +
            "   \"searchAttributes\":    [\n" +
            "        {\n" +
            "     \"name\": \"mail\",\n" +
            "     \"returnAsList\": false,\n" +
            "     \"returnName\": \"email\"\n" +
            "    },\n" +
            "        {\n" +
            "     \"name\": \"uid\",\n" +
            "     \"returnAsList\": false,\n" +
            "     \"returnName\": \"uid\"\n" +
            "    },\n" +
            "        {\n" +
            "     \"name\": \"uid\",\n" +
            "     \"returnAsList\": false,\n" +
            "     \"returnName\": \"uid\"\n" +
            "    },\n" +
            "        {\n" +
            "     \"name\": \"uidNumber\",\n" +
            "     \"returnAsList\": false,\n" +
            "     \"returnName\": \"uidNumber\"\n" +
            "    },\n" +
            "        {\n" +
            "     \"name\": \"cn\",\n" +
            "     \"returnAsList\": false,\n" +
            "     \"returnName\": \"name\"\n" +
            "    },\n" +
            "        {\n" +
            "     \"name\": \"memberOf\",\n" +
            "     \"isGroup\": true,\n" +
            "     \"returnAsList\": false,\n" +
            "     \"returnName\": \"isMemberOf\"\n" +
            "    }\n" +
            "   ],\n" +
            "   \"searchBase\": \"ou=People,dc=ncsa,dc=illinois,dc=edu\",\n" +
            "   \"contextName\": \"\",\n" +
            "   \"ssl\":    {\n" +
            "    \"tlsVersion\": \"TLS\",\n" +
            "    \"useJavaTrustStore\": true\n" +
            "   },\n" +
            "   \"name\": \"3258ed63b62d1a78\"\n" +
            "  }}],\n" +
            "  \"preProcessing\": [  {\n" +
            "   \"$if\": [\"$true\"],\n" +
            "   \"$then\": [{\"$set_claim_source\":    [\n" +
            "    \"LDAP\",\n" +
            "    \"3258ed63b62d1a78\"\n" +
            "   ]}]\n" +
            "  }],\n" +
            "  \"postProcessing\": {\"$xor\":   [\n" +
            "      {\n" +
            "    \"$if\": [{\"$hasClaim\": [\"eppn\"]}],\n" +
            "    \"$then\": [{\"$set\":     [\n" +
            "     \"voPersonExternalID\",\n" +
            "     {\"$get\": [\"eppn\"]}\n" +
            "    ]}]\n" +
            "   },\n" +
            "      {\n" +
            "    \"$if\": [{\"$hasClaim\": [\"eptid\"]}],\n" +
            "    \"$then\": [{\"$set\":     [\n" +
            "     \"voPersonExternalID\",\n" +
            "     {\"$get\": [\"eptid\"]}\n" +
            "    ]}]\n" +
            "   },\n" +
            "      {\n" +
            "    \"$if\": [{\"$equals\":     [\n" +
            "     {\"$get\": [\"idp\"]},\n" +
            "     \"http://github.com/login/oauth/authorize\"\n" +
            "    ]}],\n" +
            "    \"$then\": [{\"$set\":     [\n" +
            "     \"voPersonExternalID\",\n" +
            "     {\"$concat\":      [\n" +
            "      {\"$get\": [\"oidc\"]},\n" +
            "      \"@github.com\"\n" +
            "     ]}\n" +
            "    ]}]\n" +
            "   },\n" +
            "      {\n" +
            "    \"$if\": [{\"$equals\":     [\n" +
            "     {\"$get\": [\"idp\"]},\n" +
            "     \"http://google.com/accounts/o8/id\"\n" +
            "    ]}],\n" +
            "    \"$then\": [{\"$set\":     [\n" +
            "     \"voPersonExternalID\",\n" +
            "     {\"$concat\":      [\n" +
            "      {\"$get\": [\"oidc\"]},\n" +
            "      \"@accounts.google.com\"\n" +
            "     ]}\n" +
            "    ]}]\n" +
            "   },\n" +
            "      {\n" +
            "    \"$if\": [{\"$equals\":     [\n" +
            "     {\"$get\": [\"idp\"]},\n" +
            "     \"http://orcid.org/oauth/authorize\"\n" +
            "    ]}],\n" +
            "    \"$then\": [{\"$set\":     [\n" +
            "     \"voPersonExternalID\",\n" +
            "     {\"$replace\":      [\n" +
            "      {\"$get\": [\"oidc\"]},\n" +
            "      \"http://\",\n" +
            "      \"https://\"\n" +
            "     ]}\n" +
            "    ]}]\n" +
            "   }\n" +
            "  ]}\n" +
            " },\n" +
            " \"isSaved\": true\n" +
            "}";

    static String cmextra = "{\"client_id\":\"oidc:jeff/client\",\n" +
            "  \"client_secret\":\"my_totally_cool_secret\",\n" +
            "  \"cfg\": {\"isSaved\": true,\"qdl\": [\"a\",\"b\"]}}\n";
}
