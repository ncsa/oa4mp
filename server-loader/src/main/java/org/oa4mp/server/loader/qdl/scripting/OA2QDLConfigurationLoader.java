package org.oa4mp.server.loader.qdl.scripting;

import org.qdl_lang.config.QDLConfigurationLoader;
import org.qdl_lang.scripting.AnotherJSONUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.List;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstNode;
import static edu.uiuc.ncsa.security.core.configuration.Configurations.getNodeValue;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/29/22 at  9:31 AM
 */
public class OA2QDLConfigurationLoader<T extends OA2QDLEnvironment> extends QDLConfigurationLoader<T> {
    public OA2QDLConfigurationLoader(String cfgFile, ConfigurationNode node) {
        super(cfgFile, node);
    }

    public OA2QDLConfigurationLoader(String cfgFile, ConfigurationNode node, MyLoggingFacade logger) {
        super(cfgFile, node, logger);
    }

    @Override
    public T createInstance() {
        return (T) new OA2QDLEnvironment(
                myLogger,
                getConfigFile(),
                getName(),
                isEnabled(),
                isServerModeOn(),
                isRestrictedIO(),
                getNumericDigits(),
                getBootScript(),
                getWSHomeDir(),
                getWSEnvFile(),
                isEchoModeOn(),
                isPrettyPrint(),
                isWSVerboseOn(),
                getCompressionOn(),
                showBanner(),
                getVFSConfigs(),
                getModuleConfigs(),
                getScriptPath(),
                getModulePath(),
                getLibPath(),
                getDebugLevel(),
                isAutosaveOn(),
                getAutosaveInterval(),
                isAutosaveMessagesOn(),
                useWSExternalEditor(),
                getExternalEditorPath(),
                getEditors(),
                isEnableLibrarySupport(),
                areAssertionsEnabled(),
                getSaveDir(),
                isOverwriteBaseFunctionsOn(),
                getServerScriptSet(),
                getLibLoader(),
                useLogo(),
                isSkipBadModulesOnLoad(),
                isPreprocessorOn());
    }

    Boolean skipBadModulesOnLoad = null;

    private boolean isSkipBadModulesOnLoad() {
        // Fix CIL-1772
        if (skipBadModulesOnLoad == null) {
            String x = getNodeValue(cn, SKIP_BAD_MODULES_TAG);
            if (x == null) {
                skipBadModulesOnLoad = true; // default
            } else {
                skipBadModulesOnLoad = x.equalsIgnoreCase("true");
            }
        }
        return skipBadModulesOnLoad;
    }

    public static String SCRIPTS_TAG = "scripts";
    public static String SCRIPT_TAG = "script";
    public static String SKIP_BAD_MODULES_TAG = "skipBadModulesOnLoad";

    protected String getWSEnvFile() {
        ConfigurationNode node = getFirstNode(cn, WS_TAG);
        return getNodeValue(node, WS_ENV, "");
    }

    public ScriptSet getServerScriptSet() {
        ConfigurationNode node = getFirstNode(cn, SCRIPTS_TAG);
        if (node == null) {
            // no scripts.
            return null;
        }
        List<ConfigurationNode> scripts = node.getChildren(SCRIPT_TAG);
        if (scripts == null || scripts.isEmpty()) {
            return null;
        }
        JSONArray allScripts = new JSONArray();

        for (ConfigurationNode scriptNode : scripts) {
            String rawJSON = (String) scriptNode.getValue();
            if (rawJSON != null && !rawJSON.trim().isEmpty()) {
                // skip empty tags
                JSONObject jsonObject = JSONObject.fromObject(rawJSON);
                Object o = jsonObject.get("qdl");
                if(!(o instanceof JSON)){
                    // skip it. What the heck?
                    continue;
                }
                if(o instanceof JSONArray){
                   allScripts.addAll((JSONArray)o);
                }
                if(o instanceof JSONObject){
                    allScripts.add(o);
                }
            }
        }
        return AnaphorUtil.createScripts(allScripts);
    }
}
