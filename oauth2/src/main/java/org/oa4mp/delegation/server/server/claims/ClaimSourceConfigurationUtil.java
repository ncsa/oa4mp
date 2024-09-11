package org.oa4mp.delegation.server.server.claims;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.JSONUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstAttribute;
import static edu.uiuc.ncsa.security.core.configuration.Configurations.getNodeValue;
import static org.oa4mp.delegation.server.server.scripts.functor.ClientFunctorScriptsUtil.CLAIM_POST_PROCESSING_KEY;
import static org.oa4mp.delegation.server.server.scripts.functor.ClientFunctorScriptsUtil.CLAIM_PRE_PROCESSING_KEY;

/**
 * This is a utility that will take a claim source and make a configuration for it.
 * <p>Created by Jeff Gaynor<br>
 * on 7/23/18 at  3:49 PM
 */
public class ClaimSourceConfigurationUtil {
    public static final String ID_TAG = "id";
    public static final String NAME_TAG = "name";
    public static final String ENABLED_TAG = "enabled";
    public static final String FAIL_ON_ERROR_TAG = "failOnError";
    public static final String NOTIFY_ON_FAIL_TAG = "notifyOnFail";
    public static final String OMIT_CLAIMS_LIST_TAG = "omitClaimsList";

    public String getComponentName() {
        return "default";
    }

    /**
     * Returns if the JSON is the type for for this utility. The basic form of a JSON object for this is
     * <pre>
     *     {"type":{config}}
     * </pre>
     * and all this does is check that the type matches the {@link #getComponentName()}.
     *
     * @param jsonObject
     * @return
     */
    public boolean isInstanceOf(JSONObject jsonObject) {
        return jsonObject.containsKey(getComponentName());
    }

    /**
     * Override as needed to create a new configuration of the right type.
     *
     * @return
     */
    public ClaimSourceConfiguration createConfiguration() {
        return new ClaimSourceConfiguration();
    }

    /**
     * Populate a {@link ClaimSourceConfiguration}
     * <b><i>NOTE</i></b> the node is assumed to be for the form {"componentName":{}} where the key is the component name
     * is the claim source, e.g. ldap that is used. The default is "default". The vlaue is the actual configuration.
     * This lets you stick these all over
     * the place and they stay encapsulated nicely in JSON configuration files.
     * <p>
     * The value will be of the form {"enabled":"true",...} (so all the tags are top-level in it).
     *
     * @param logger
     * @param node
     * @return
     */
    public ClaimSourceConfiguration getConfiguration(
            MyLoggingFacade logger,
            ConfigurationNode node) {
        ClaimSourceConfiguration config = createConfiguration();
        if (node == null) {
            logger.info("No claim source configuration found.");
            config.setEnabled(false);
            return config;
        }
        config.setEnabled(true); //default
        String x = getFirstAttribute(node, ENABLED_TAG);
        if (x != null) {
            try {
                config.setEnabled(Boolean.parseBoolean(x));
            } catch (Throwable t) {
                logger.warn("Could not parsed enabled flag value of \"" + x + "\". Assuming configuration is enabled.");
            }
        }

        String name = getNodeValue(node, NAME_TAG);
        String id = getNodeValue(node, ID_TAG);
        config.setName(name);
        config.setId(id);
        String errs = getNodeValue(node, FAIL_ON_ERROR_TAG);
        if (!(errs == null || errs.length() == 0)) {
            config.setFailOnError(Boolean.getBoolean(errs));
        }
        errs = getNodeValue(node, NOTIFY_ON_FAIL_TAG);
        if (!(errs == null || errs.length() == 0)) {
            config.setNotifyOnFail(Boolean.getBoolean(errs));
        }
       String omitList = getNodeValue(node, OMIT_CLAIMS_LIST_TAG);
        if(omitList!= null && !omitList.isEmpty()){
            JSONArray array = JSONArray.fromObject(omitList);
            config.setOmitList(array);
        }
        return config;
    }


    /**
     * Note that is is assumed that the json object is the correct
     *
     * @param config
     * @return
     */
    public JSONObject toJSON(ClaimSourceConfiguration config) {
        JSONUtil jsonUtil = getJSONUtil();
        JSONObject jsonConfig = new JSONObject();
        JSONObject content = new JSONObject();
        jsonConfig.put(getComponentName(), content);
        jsonUtil.setJSONValue(jsonConfig, ID_TAG, config.getId());
        jsonUtil.setJSONValue(jsonConfig, NAME_TAG, config.getName());
        jsonUtil.setJSONValue(jsonConfig, ENABLED_TAG, config.isEnabled());
        jsonUtil.setJSONValue(jsonConfig, FAIL_ON_ERROR_TAG, config.isFailOnError());
        jsonUtil.setJSONValue(jsonConfig, NOTIFY_ON_FAIL_TAG, config.isNotifyOnFail());
        jsonUtil.setJSONValue(jsonConfig, CLAIM_PRE_PROCESSING_KEY, config.getRawPreProcessor());
        jsonUtil.setJSONValue(jsonConfig, CLAIM_POST_PROCESSING_KEY, config.getRawPostProcessor());
        if (config.getOmitList() != null && !config.getOmitList().isEmpty()) {
            JSONArray omitList = null;
            if (config.getOmitList() instanceof JSONArray) {
                jsonUtil.setJSONValue(jsonConfig, OMIT_CLAIMS_LIST_TAG, config.getOmitList());
            } else {
                omitList = new JSONArray();
                omitList.addAll(config.getOmitList());
                jsonUtil.setJSONValue(jsonConfig, OMIT_CLAIMS_LIST_TAG, omitList);
            }
        }

        return jsonConfig;
    }


    /**
     * Populate and <b><i>existing</i></b> configuration.
     *
     * @param config
     * @param json
     * @return
     */
    public ClaimSourceConfiguration fromJSON(ClaimSourceConfiguration config, JSONObject json) {
        JSONUtil jsonUtil = getJSONUtil();
        if (config == null) {
            config = createConfiguration();
        }

        config.setId(jsonUtil.getJSONValueString(json, ID_TAG));
        config.setName(jsonUtil.getJSONValueString(json, NAME_TAG));
        config.setEnabled(jsonUtil.getJSONValueBoolean(json, ENABLED_TAG));
        if (jsonUtil.hasKey(json, FAIL_ON_ERROR_TAG)) {
            config.setFailOnError(jsonUtil.getJSONValueBoolean(json, FAIL_ON_ERROR_TAG));
        }
        if (jsonUtil.hasKey(json, NOTIFY_ON_FAIL_TAG)) {
            config.setNotifyOnFail(jsonUtil.getJSONValueBoolean(json, NOTIFY_ON_FAIL_TAG));
        }
        // CIL-513 fix
        Object rawOmitList = jsonUtil.getJSONValue(json, OMIT_CLAIMS_LIST_TAG);
        if (rawOmitList == null) {
            config.setOmitList(new JSONArray());
        }else{
            JSONArray array = null;
            if (rawOmitList instanceof JSONArray) {
                array = (JSONArray) rawOmitList;
            } else {
                array = JSONArray.fromObject(rawOmitList);
            }
            config.setOmitList(array);
        }
        config.setRawPreProcessor(jsonUtil.getJSONValueString(json, CLAIM_PRE_PROCESSING_KEY));
        config.setRawPostProcessor(jsonUtil.getJSONValueString(json, CLAIM_POST_PROCESSING_KEY));
        config.setProperties(json.getJSONObject(getComponentName()));
        return config;
    }

    JSONUtil jsonUtil = null;

    protected JSONUtil getJSONUtil() {
        if (jsonUtil == null) {
            jsonUtil = new JSONUtil(getComponentName());
        }
        return jsonUtil;
    }


}
