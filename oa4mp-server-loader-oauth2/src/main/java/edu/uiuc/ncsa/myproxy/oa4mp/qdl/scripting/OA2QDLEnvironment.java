package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.qdl.config.ModuleConfig;
import edu.uiuc.ncsa.qdl.config.QDLEnvironment;
import edu.uiuc.ncsa.qdl.config.VFSConfig;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.editing.Editors;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/29/22 at  9:10 AM
 */
public class OA2QDLEnvironment extends QDLEnvironment {


    public OA2QDLEnvironment() {
    }

    public OA2QDLEnvironment(MyLoggingFacade myLogger,
                             String cfgFile,
                             String name,
                             boolean isEnabled,
                             boolean isServerModeOn,
                             boolean isRestrictedIO,
                             int numericDigits,
                             String bootScript,
                             String wsHomeDir,
                             String wsEnv,
                             boolean echoModeOn,
                             boolean prettyPrint,
                             boolean verboseOn,
                             boolean compressionOn,
                             boolean showBanner,
                             List<VFSConfig> vfsConfigs,
                             List<ModuleConfig> moduleConfigs,
                             String scriptPath,
                             String modulePath,
                             String libPath,
                             String debugLevel,
                             boolean autosaveOn,
                             long autosaveInterval,
                             boolean autosaveMessagesOn,
                             boolean useExternalEditor,
                             String externalEditorPath,
                             Editors qdlEditors,
                             boolean enableLibrarySupport,
                             boolean assertionsOn,
                             String saveDir,
                             boolean allowOverwriteBaseFunctions,
                             ScriptSet serverScripts) {
        super(myLogger, cfgFile, name, isEnabled, isServerModeOn, isRestrictedIO, numericDigits, bootScript, wsHomeDir, wsEnv, echoModeOn, prettyPrint, verboseOn, compressionOn, showBanner, vfsConfigs, moduleConfigs, scriptPath, modulePath, libPath, debugLevel, autosaveOn, autosaveInterval, autosaveMessagesOn, useExternalEditor, externalEditorPath, qdlEditors, enableLibrarySupport, assertionsOn, saveDir, allowOverwriteBaseFunctions);
        if (serverScripts != null && !serverScripts.isEmpty()) {
            this.serverScripts = serverScripts;
        }
    }

    public ScriptSet getServerScripts() {
        return serverScripts;
    }

    public void setServerScripts(ScriptSet serverScripts) {
        this.serverScripts = serverScripts;
    }

    ScriptSet serverScripts = null;

}
