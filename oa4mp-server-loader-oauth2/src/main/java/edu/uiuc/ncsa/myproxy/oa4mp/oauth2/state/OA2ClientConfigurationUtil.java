package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jSetClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.ClientConfigurationUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.functor.FunctorTypeImpl;
import edu.uiuc.ncsa.security.util.functor.logic.jTrue;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * This helps work with the configuration for a client. The basic format is
 * <pre>
 *    {"config":"comment",
 *      "claims":[{a0,z0},{a1,z1},{a2,z2}]
 *      "runtime":[...]
 *    }*
 * </pre>
 * Where a0,a1,... is one of
 * <ul>
 * <li>sources= list of aliases and class names</li>
 * <li>sourceConfig = configurations corresponding to the sources</li>
 * <li>processing = directives to run <b>after</b> the claims have been obtained</li>
 * </ul>
 * and
 * <pre>
 *     runtime = directives to run before any processing. E.g. A condition to determine if claims are to be gotten.
 * </pre>
 * <p>Created by Jeff Gaynor<br>
 * on 4/12/18 at  8:16 AM
 */
public class OA2ClientConfigurationUtil extends ClientConfigurationUtil {
    public static final String CONFIG_KEY = "config";
    public static final String CLAIMS_KEY = "claims";
    public static final String CLAIM_SOURCES_KEY = "sources";
    public static final String CLAIM_PROCESSING_KEY = "processing";
    public static final String CLAIM_SOURCE_CONFIG_KEY = "sourceConfig";
    public static final String SAVED_KEY = "isSaved";
    /**
     * Note that this cannot be the reserved word "class" since the JSON library will attempt to
     * resolve it to a class and do squirrelly things with it if it finds one.
     */
    public static final String CLAIM_SOURCE_CLASSNAME_KEY = "className";
    public static final String CLAIM_SOURCE_ALIAS_KEY = "alias";
       /*
       This lets me create a completely valid configuration of some complexity for testing.
        */


    public static class SourceEntry {
        public SourceEntry(Class klasse, String alias) {
            this.alias = alias;
            className = klasse.getCanonicalName();
        }

        public SourceEntry(String className, String alias) {
            this.alias = alias;
            this.className = className;
        }

        String className;
        String alias;
    }

    /**
     * Convenience method to pull the sources from a the whole configuration
     *
     * @param json
     * @return
     */
    static public Map<String, SourceEntry> toSourcesMap(JSONObject json) {
        return toSourcesMap(getClaimSources(json));

    }

    static public String getComment(JSONObject cfg){
        if(cfg.containsKey(CONFIG_KEY)){
            return cfg.getString(CONFIG_KEY);
        }
        return "";
    }

    public static void setComment(JSONObject cfg, String comment){
          cfg.put(CONFIG_KEY, comment);
    }

    /**
     * Method to pull the sources from the array of {"alias":A,"className":B} objects
     *
     * @param array
     * @return
     */
    static public Map<String, SourceEntry> toSourcesMap(JSONArray array) {
        Map<String, SourceEntry> s = new HashMap<>();
        for (int i = 0; i < array.size(); i++) {
            JSONObject x = array.getJSONObject(i);
            SourceEntry sourceEntry = new SourceEntry(x.getString(CLAIM_SOURCE_CLASSNAME_KEY), x.getString(CLAIM_SOURCE_ALIAS_KEY));
            s.put(sourceEntry.alias, sourceEntry);
        }
        return s;
    }

    static public JSONArray getClaimSources(JSONObject config) {
        return getClaimsThingy(config, CLAIM_SOURCES_KEY);
    }

    public static void setClaimSources(JSONObject config, JSONArray claimsSources) {
        setClaimsThingy(config, CLAIM_SOURCES_KEY, claimsSources);
    }

    protected static JSONArray getClaimsThingy(JSONObject config, String key) {
        if (!config.containsKey(CLAIMS_KEY)) {
            return new JSONArray();
        }
        JSONObject claims = config.getJSONObject(CLAIMS_KEY);
        Object obj = claims.get(key);
        if (obj instanceof JSONArray) {
            return (JSONArray) obj;
        }
        return new JSONArray();
    }

    protected static void setClaimsThingy(JSONObject config, String key, JSONArray thingy) {
        JSONObject claims;
        if (config.containsKey(CLAIMS_KEY)) {
            claims = config.getJSONObject(CLAIMS_KEY);
        } else {
            claims = new JSONObject();
        }
        claims.put(key, thingy);
        config.put(CLAIMS_KEY, claims);

    }


    public static JSONArray getClaimSourceConfigurations(JSONObject config) {
        return getClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY);
    }

    public static void setClaimSourcesConfigurations(JSONObject config, JSONArray sourceConfigs) {
        setClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY, sourceConfigs);
    }

    public static JSONArray getClaimsProcessing(JSONObject config) {
        return getClaimsThingy(config, CLAIM_PROCESSING_KEY);
    }

    public static void setClaimsProcessing(JSONObject config, JSONArray processing) {
        setClaimsThingy(config, CLAIM_PROCESSING_KEY, processing);
    }

    public static final String OLD_LDAP_CONFIG_NAME = "original_config";

    /**
     * This will take the old LDAP object and convert it to the new configuration format. It does this by
     * breating a new entry with a distinguished name. If that exists in the new config,
     * then it is assumed that this has been done.
     *
     * To migrate an old claim source configuration (only LDAP was explicitly supported you must either)<br/>
     * <ul>
     *     <li>let this run (it will be invoked automatically)</li>
     *     <li>explicitly migrate the old configuration by hand and set up a corresponding conditional.</li>
     * </ul>
     * @param oldLDAP the raw JSON of the old LDAP configuration in the store. Delete this from the store when done!
     * @param config the new configuration object
     * @return
     */
    public static JSONObject convertToNewConfiguration(JSONObject oldLDAP, JSONObject config) {
        JSONArray claimSources = getClaimSourceConfigurations(config);
        boolean containsOldLDAP = false;
        for (int i = 0; i < claimSources.size(); i++) {
            try {
                JSONObject obj = claimSources.getJSONObject(i);
                containsOldLDAP = containsOldLDAP || obj.containsKey(LDAPConfigurationUtil.CONFIGURATION_NAME_KEY);
            } catch (Throwable t) {
                // If this fails, we don't care.
            }
        }
        if (!containsOldLDAP) {
            JSONObject content = oldLDAP.getJSONObject(LDAPConfigurationUtil.LDAP_TAG);
            content.put(LDAPConfigurationUtil.CONFIGURATION_NAME_KEY, OLD_LDAP_CONFIG_NAME);
            // have to do this since JSON libraries clones things and we need to make sure this is updated.
            oldLDAP.put(LDAPConfigurationUtil.LDAP_TAG, content);
            claimSources.add(oldLDAP);
            setClaimSourcesConfigurations(config, claimSources);
            JSONObject ifBlock = new JSONObject();

            jTrue jTrue = new jTrue();
            ifBlock.put(FunctorTypeImpl.IF.getValue(), jTrue.toJSON());

            JSONObject thenBlock = new JSONObject();

            jSetClaimSource jSetClaimSource = new jSetClaimSource();
            jSetClaimSource.addArg(OA2ClientConfigurationFactory.LDAP_DEFAULT);
            jSetClaimSource.addArg(OLD_LDAP_CONFIG_NAME);

            ifBlock.put(FunctorTypeImpl.THEN.getValue(), jSetClaimSource.toJSON());
            // this creates the correct ifBlock.
            JSONArray runtime = getRuntime(config);
            runtime.add(ifBlock);
            setRuntime(config, runtime);
        }
        return config;

    }
   public static boolean isSaved(JSONObject config){
       if(config.containsKey(SAVED_KEY)){
           return config.getBoolean(SAVED_KEY);
       }

       return true;
   }
    public static void setSaved(JSONObject config, boolean value){
        config.put(SAVED_KEY, value);
    }
}
