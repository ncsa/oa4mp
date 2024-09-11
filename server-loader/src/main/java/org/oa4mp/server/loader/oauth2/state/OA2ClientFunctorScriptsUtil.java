package org.oa4mp.server.loader.oauth2.state;

import org.oa4mp.server.loader.oauth2.flows.jSetClaimSource;
import org.oa4mp.server.loader.oauth2.functor.claims.OA2FunctorFactory;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import org.oa4mp.delegation.server.server.scripts.functor.ClientFunctorScriptsUtil;
import edu.uiuc.ncsa.security.util.functor.FunctorTypeImpl;
import edu.uiuc.ncsa.security.util.functor.LogicBlock;
import edu.uiuc.ncsa.security.util.functor.LogicBlocks;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.oa4mp.delegation.server.server.claims.ClaimSourceConfigurationUtil.ID_TAG;
import static org.oa4mp.delegation.server.server.config.LDAPConfigurationUtil.LDAP_TAG;

/**
 * This helps work with the configuration for a client. The basic format is
 * <pre>
 *    {"config":"comment",
 *      "claims":{
 *         "runtime":[...],
 *         "sources:[{"alias":"A","className":"B"},...],
 *         "sourcesConfig":[{config1,...}],
 *         "preProcessing":[],
 *         "postProcessing":[]
 *      }
 *    }*
 * </pre>
 * Where
 * <ul>
 * <li>sources= list of aliases and class names, </li>
 * <li>sourceConfig = configurations corresponding to the sources</li>
 * <li>preProcessing = directives to run <b>before</b> the claims have been obtained</li>
 * <li>postProcessing = directives to run <b>after</b> the claims have been obtained</li>
 * </ul>
 * and
 * <pre>
 *     runtime = directives to run before any processing. E.g. A condition to determine if claims are to be gotten.
 * </pre>
 * The sourcesConfigurations are a list of configurations for the claim sources. This allows for multiple configurations
 * to be used (e,g. depending on the IDP,  specific LDAP claim sources will be invoked.)
 * <p>Created by Jeff Gaynor<br>
 * on 4/12/18 at  8:16 AM
 */
public class OA2ClientFunctorScriptsUtil extends ClientFunctorScriptsUtil {
    public static final String CONFIG_KEY = "config";
    public static final String CLAIMS_KEY = "claims";
    public static final String CLAIM_SOURCES_KEY = "sources";

    public static final String CLAIM_SOURCE_CONFIG_KEY = "sourceConfig";
    /**
     * Note that this cannot be the reserved word "class" since the JSON library will attempt to
     * resolve it to a class and do squirrelly things with it if it finds one.
     */
    public static final String CLAIM_SOURCE_CLASSNAME_KEY = "className";
    public static final String CLAIM_SOURCE_ALIAS_KEY = "alias";


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


    protected static JSONObject getClaimsProcessor(JSONObject config, String key) {
        String dbgName = "getClaimsProcessor";

        if(config.containsKey(ID_TAG)){
            dbgName = dbgName + "(" + config.getString(ID_TAG) + ")";
        }
        dbgName = dbgName + ":";
        DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, dbgName + " key=" + key);
        if (!config.containsKey(CLAIMS_KEY)) {
            DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, dbgName + " NO CLAIMS");
            return new JSONObject();
        }

        JSONObject claims = config.getJSONObject(CLAIMS_KEY);
        Object obj = claims.get(key);
        DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, dbgName + "JSON configuration object for this key=" + obj);

        if (obj instanceof JSONArray) {
            DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "object is a JSON Array");
            JSONObject j = new JSONObject();
            j.put(FunctorTypeImpl.OR.getValue(), obj);
            return j;
        }
        if (obj instanceof JSONObject) {
            DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "Got a JSON object.");

            return (JSONObject) obj;
        }
        DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "object found is \"" + obj + "\"");
        DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "Object not recognized, returning empty object.");

        return new JSONObject();
    }


    protected static void setClaimsThingy(JSONObject config, String key, JSON thingy) {
       setThingy(CLAIMS_KEY, config, key, thingy);
    }

    public static boolean hasClaimPreProcessor(JSONObject config) {
        return hasClaimsThingy(CLAIM_PRE_PROCESSING_KEY, config);
    }

    public static boolean hasClaimPostProcessor(JSONObject config) {
        return hasClaimsThingy(CLAIM_POST_PROCESSING_KEY, config);
    }

    public static boolean hasClaimSources(JSONObject config) {
        return hasClaimsThingy(CLAIM_SOURCES_KEY, config);
    }

    public static boolean hasClaimSourceConfigurations(JSONObject config) {
        return hasClaimsThingy(CLAIM_SOURCE_CONFIG_KEY, config);
    }


    protected static boolean hasClaimsThingy(String key, JSONObject config) {
      return hasThingy(CLAIMS_KEY, key, config);
    }

    public static JSONArray getClaimSourceConfigurations(JSONObject config) {
        return getClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY);
    }

    public static void setClaimSourcesConfigurations(JSONObject config, JSONArray sourceConfigs) {
        setClaimsThingy(config, CLAIM_SOURCE_CONFIG_KEY, sourceConfigs);
    }

    public static JSONObject getClaimsPostProcessing(JSONObject config) {
        return getClaimsProcessor(config, CLAIM_POST_PROCESSING_KEY);
    }

    public static void setClaimsPostProcessing(JSONObject config, JSONObject processing) {
        setClaimsThingy(config, CLAIM_POST_PROCESSING_KEY, processing);
    }


    public static JSONObject getClaimsPreProcessing(JSONObject config) {
        return getClaimsProcessor(config, CLAIM_PRE_PROCESSING_KEY);
    }

    public static void setClaimsPreProcessing(JSONObject config, JSONObject processing) {
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
        // now to figure out the id. Sometime people use the name field instead.


        if (content.containsKey(ID_TAG) && !content.getString(ID_TAG).isEmpty()) {
            String oldLDAPName = content.getString(ID_TAG);

            // the old LDAP config contains a name, so we check if it is in the current list of thse
            for (int i = 0; i < claimSources.size(); i++) {
                try {
                    JSONObject obj = claimSources.getJSONObject(i);
                    JSONObject currentContent = obj.getJSONObject(LDAP_TAG);
                    if (currentContent.getString(ID_TAG).equals(oldLDAPName)) {
                        containsOldLDAP = true;
                        break;
                    }
                } catch (Throwable t) {
                    // If this fails, we don't care.
                }
            }
            if (!containsOldLDAP) {
                DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "This does not contain the existing LDAP. Adding it.");

                // Add it to the list of configurations.
                claimSources.add(oldLDAP);
            //    setSaved(config, false);
                // update the set of claims sources in the configuration.
                setClaimSourcesConfigurations(config, claimSources);
                if (!hasClaimPreProcessor(config) && !hasRuntime(config)) {
                    DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "Claim sources does not include old LDAP. No runtime/pre-processor, so creating default.");
                    createDefaultPreProcessor(config, oldLDAPName);
                }
            }

        } else {
            // the current content has no key. Then we create a new key and include it.
            SecureRandom secureRandom = new SecureRandom();
            long newValue = secureRandom.nextLong();
            String newName = Long.toHexString(newValue);
            content.put(ID_TAG, newName);
            DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, ".convertToNewConfig: old LDAP size =" + oldLDAP.size() + ", keyset = " + oldLDAP.keySet());
            oldLDAP.put(LDAP_TAG, content);
            claimSources.add(oldLDAP);
            setClaimSourcesConfigurations(config, claimSources);
        //    setSaved(config, false);
            // Finally, if there is NO claims pre-processor (which would set the source to use
            // then create one. Otherwise leave any existing new configuration intact.
            DebugUtil.trace(OA2ClientFunctorScriptsUtil.class, "Done creating new Claim source with id = " + newName + ". Create default processor?" +
                    (!OA2ClientFunctorScriptsUtil.hasClaimPreProcessor(config) && !hasRuntime(config)));
            if (!hasClaimPreProcessor(config) && !hasRuntime(config)) {
                createDefaultPreProcessor(config, newName);
            }

        }

        return config;

    }

    protected static void createDefaultPreProcessor(JSONObject config, String newName) {
        JSONArray array = new JSONArray();
        JSONObject emptyClaims = new JSONObject();
        Collection<String> emptyScopes= new ArrayList();
        OA2FunctorFactory ff = new OA2FunctorFactory(emptyClaims, emptyScopes); // need the factory, but there are no claims or scopes at this point.
        jSetClaimSource jSetClaimSource = new jSetClaimSource();
        jSetClaimSource.addArg(OA2ClientFunctorScriptsFactory.LDAP_DEFAULT);
        jSetClaimSource.addArg(newName);
        array.add(jSetClaimSource.toJSON());
        JSONObject j = new JSONObject();
        j.put(FunctorTypeImpl.OR.getValue(), array);
        LogicBlocks<? extends LogicBlock> defaultLBs = ff.createLogicBlock(j);
        setClaimsPreProcessing(config, defaultLBs.toJSON());
    }

}
