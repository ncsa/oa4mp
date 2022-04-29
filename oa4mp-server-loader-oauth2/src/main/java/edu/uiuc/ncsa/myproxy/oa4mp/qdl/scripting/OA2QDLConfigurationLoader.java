package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.qdl.config.QDLConfigurationLoader;
import edu.uiuc.ncsa.qdl.scripting.AnotherJSONUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.List;

import static edu.uiuc.ncsa.qdl.scripting.Scripts.CODE;
import static edu.uiuc.ncsa.qdl.scripting.Scripts.RUN;
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
                getServerScriptSet());
    }

    /*
            <scripts>
              <qdl>
                 <load>y.qdl</load>
                 <xmd>{"exec_phase":"pre_auth":,"token_type":"access"}</xmd>
                 <args>[4,true,{"server":"localhost","port":443"}]</args>
              </qdl>

            {"qdl":
               {
                 "load":"y.qdl",
                  "xmd":{"exec_phase":"pre_auth":,"token_type":"access"},
                 "args":[4,true,{"server":"localhost","port":443"}]
              }}

             <qdl>
                <code>["x:=to_uri(claims.uid).path;","claims.my_id:=x-'/server'-'/users/';"]</code>
                <xmd>{"exec_phase":"pre_token"}</xmd>
              </qdl>
            </scripts>

            {"qdl":{
               "code":["x:=to_uri(claims.uid).path;","claims.my_id:=x-'/server'-'/users/';"],
               "xmd":{"exec_phase":"pre_token"}
            }}



             */
    public static String SCRIPTS_TAG = "scripts";
    public static String SCRIPT_TAG = "script";

    protected String getWSEnvFile() {
        ConfigurationNode node = getFirstNode(cn, WS_TAG);
        return getNodeValue(node, WS_ENV, "");
    }

    public ScriptSet getServerScriptSet2() {
        ConfigurationNode node = getFirstNode(cn, SCRIPTS_TAG);
        List<ConfigurationNode> scripts = node.getChildren(SCRIPT_TAG);
        if (scripts == null || scripts.isEmpty()) {
            return null;
        }
        JSONArray allScripts = new JSONArray();

        for (ConfigurationNode scriptNode : scripts) {

            String run = getNodeValue(scriptNode, RUN);
            String code = getNodeValue(scriptNode, CODE);
            String xmd = getNodeValue(scriptNode, AnotherJSONUtil.XMD_TAG); // JSON
            String args = getNodeValue(scriptNode, AnotherJSONUtil.ARGS_TAG); // JSON
            JSONObject inner = new JSONObject();

            if (!StringUtils.isTrivial(xmd)) {
                inner.put(AnotherJSONUtil.XMD_TAG, JSONObject.fromObject(xmd));
            }
            if (!StringUtils.isTrivial(args)) {
                inner.put(AnotherJSONUtil.ARGS_TAG, JSONArray.fromObject(args));
            }
            if (!StringUtils.isTrivial(run)) {
                inner.put(RUN, run);
            }
            if (!StringUtils.isTrivial(code)) {
                // cases are that it is a single line or that it is a JSON array of lines.
                JSONArray lines;
                try {
                    lines = JSONArray.fromObject(code);
                } catch (Throwable t) {
                    lines = new JSONArray();
                    lines.add(code);// wrap the line. It's QDL's problem now
                }
                inner.put(CODE, lines);
            }
            JSONObject s = new JSONObject();
            s.put("qdl", inner);
            allScripts.add(s);
        }
        return AnotherJSONUtil.createScripts(allScripts);
    }


    public ScriptSet getServerScriptSet() {
        ConfigurationNode node = getFirstNode(cn, SCRIPTS_TAG);
        if(node == null){
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
            if(rawJSON !=null && !rawJSON.trim().isEmpty()) {
                // skip empty tags
                allScripts.add(JSONObject.fromObject(rawJSON));
            }
        }
        return AnotherJSONUtil.createScripts(allScripts);
    }
}
