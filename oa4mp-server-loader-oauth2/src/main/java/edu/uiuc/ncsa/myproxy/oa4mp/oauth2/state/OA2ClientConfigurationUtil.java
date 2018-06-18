package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.jSetClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.ClientConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil.CONFIGURATION_NAME_KEY;
import static edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil.LDAP_TAG;

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

    static public String getComment(JSONObject cfg) {
        if (cfg.containsKey(CONFIG_KEY)) {
            return cfg.getString(CONFIG_KEY);
        }
        return "";
    }

    public static void setComment(JSONObject cfg, String comment) {
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

    public static boolean hasClaimPreProcessor(JSONObject config) {
        return hasClaimsThingy(config, CLAIM_PRE_PROCESSING_KEY);
    }

    public static boolean hasClaimPostProcessor(JSONObject config) {
        return hasClaimsThingy(config, CLAIM_POST_PROCESSING_KEY);
    }

    public static boolean hasClaimSources(JSONObject config) {
        return hasClaimsThingy(config, CLAIM_SOURCES_KEY);
    }

    public static boolean hasClaimSourceConfigurations(JSONObject config) {
        return hasClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY);
    }


    protected static boolean hasClaimsThingy(JSONObject config, String key) {
        JSONObject claims;
        if (config.containsKey(CLAIMS_KEY)) {
            claims = config.getJSONObject(CLAIMS_KEY);
        } else {
            claims = new JSONObject();
        }
        return claims.containsKey(key);
    }

    public static JSONArray getClaimSourceConfigurations(JSONObject config) {
        return getClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY);
    }

    public static void setClaimSourcesConfigurations(JSONObject config, JSONArray sourceConfigs) {
        setClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY, sourceConfigs);
    }

    public static JSONArray getClaimsPostProcessing(JSONObject config) {
        return getClaimsThingy(config, CLAIM_POST_PROCESSING_KEY);
    }

    public static void setClaimsPostProcessing(JSONObject config, JSONArray processing) {
        setClaimsThingy(config, CLAIM_POST_PROCESSING_KEY, processing);
    }


    public static JSONArray getClaimsPreProcessing(JSONObject config) {
        return getClaimsThingy(config, CLAIM_PRE_PROCESSING_KEY);
    }

    public static void setClaimsPreProcessing(JSONObject config, JSONArray processing) {
        setClaimsThingy(config, CLAIM_PRE_PROCESSING_KEY, processing);
    }

    /**
     * This will take the old LDAP object and convert it to the new configuration format. It does this by
     * creating a new entry with a distinguished name. If that exists in the new config,
     * then it is assumed that this has been done.
     * <p/>
     * To migrate an old claim source configuration (only LDAP was explicitly supported you must either)<br/>
     * <ul>
     * <li>let this run (it will be invoked automatically)</li>
     * <li>explicitly migrate the old configuration by hand and set up a corresponding conditional.</li>
     * </ul>
     *
     * @param oldLDAP the raw JSON of the old LDAP configuration in the store. Delete this from the store when done!
     * @param config  the new configuration object
     * @return
     */
    public static JSONObject convertToNewConfiguration(JSONObject oldLDAP, JSONObject config) {
        JSONArray claimSources = getClaimSourceConfigurations(config);
        JSONObject content = oldLDAP.getJSONObject(LDAP_TAG);

        boolean containsOldLDAP = false;

        if (content.containsKey(CONFIGURATION_NAME_KEY)) {
            String oldLDAPName = content.getString(CONFIGURATION_NAME_KEY);

            // the old LDAP config contains a name, so we check if it is in the current list of thse
            for (int i = 0; i < claimSources.size(); i++) {
                try {
                    JSONObject obj = claimSources.getJSONObject(i);
                    JSONObject currentContent = obj.getJSONObject(LDAP_TAG);
                    if (currentContent.getString(CONFIGURATION_NAME_KEY).equals(oldLDAPName)) {
                        containsOldLDAP = true;
                        break;
                    }
                } catch (Throwable t) {
                    // If this fails, we don't care.
                }
            }
            if (!containsOldLDAP) {
                ServletDebugUtil.dbg(OA2ClientConfigurationUtil.class, "This does not contain the existing LDAP. Adding it.");

                // Add it to the list of configurations.
                claimSources.add(oldLDAP);
                setSaved(config, false);
                // update the set of claims sources in the configuration.
                setClaimSourcesConfigurations(config, claimSources);
                if (!hasClaimPreProcessor(config) && !hasRuntime(config)) {
                    ServletDebugUtil.dbg(OA2ClientConfigurationUtil.class, "Claim sources does not include old LDAP. No runtime/pre-processor, so creating default.");
                    createDefaultPreProcessor(config, oldLDAPName);
                }
            }

        } else {
            // the current content has no key. Then we create a new key and include it.
            SecureRandom secureRandom = new SecureRandom();
            long newValue = secureRandom.nextLong();
            String newName = Long.toHexString(newValue);
            content.put(CONFIGURATION_NAME_KEY, newName);
            oldLDAP.put(LDAP_TAG, content);
            claimSources.add(oldLDAP);
            setClaimSourcesConfigurations(config, claimSources);
            setSaved(config, false);
            // Finally, if there is NO claims pre-processor (which would set the source to use
            // then create one. Otherwise leave any existing new configuration intact.
            ServletDebugUtil.dbg(OA2ClientConfigurationUtil.class, "Done creating new Claim source with id = " + newName + ". Create default processor?" +
                    (!OA2ClientConfigurationUtil.hasClaimPreProcessor(config) && !hasRuntime(config)));
            if (!hasClaimPreProcessor(config) && !hasRuntime(config)) {
                createDefaultPreProcessor(config, newName);
            }

        }

        return config;

    }

    protected static void createDefaultPreProcessor(JSONObject config, String newName) {
        JSONArray array = new JSONArray();
        JFunctorFactory ff = new JFunctorFactory();
        jSetClaimSource jSetClaimSource = new jSetClaimSource();
        jSetClaimSource.addArg(OA2ClientConfigurationFactory.LDAP_DEFAULT);
        jSetClaimSource.addArg(newName);
        array.add(jSetClaimSource.toJSON());
        LogicBlocks<? extends LogicBlock> defaultLBs = ff.createLogicBlock(array);
        // there should be one and we need it.
        LogicBlock lb = defaultLBs.get(0);
        JSONArray runtime = getRuntime(config);
        JSONObject ifBlock = JSONObject.fromObject(lb.toString());
        runtime.add(ifBlock);
        setClaimsPreProcessing(config, runtime);
    }

    public static boolean isSaved(JSONObject config) {
        if (config.containsKey(SAVED_KEY)) {
            return config.getBoolean(SAVED_KEY);
        }

        return true;
    }

    public static void setSaved(JSONObject config, boolean value) {
        config.put(SAVED_KEY, value);
    }
}
