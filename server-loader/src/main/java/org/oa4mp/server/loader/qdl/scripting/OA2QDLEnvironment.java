package org.oa4mp.server.loader.qdl.scripting;

import org.qdl_lang.config.ModuleConfig;
import org.qdl_lang.config.QDLEnvironment;
import org.qdl_lang.config.VFSConfig;
import org.qdl_lang.state.LibLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.editing.Editors;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import java.util.List;

/**
 * Environment in OA4MP for QDL.
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
                             ScriptSet serverScripts,
                             LibLoader libLoader,
                             String logo,
                             boolean skipBadModulesOnLoad) {
        super(myLogger,
                cfgFile,
                name,
                isEnabled,
                isServerModeOn,
                isRestrictedIO,
                numericDigits,
                bootScript,
                wsHomeDir,
                wsEnv,
                echoModeOn,
                prettyPrint,
                verboseOn,
                compressionOn,
                showBanner,
                vfsConfigs,
                moduleConfigs,
                scriptPath,
                modulePath,
                libPath,
                debugLevel,
                autosaveOn,
                autosaveInterval,
                autosaveMessagesOn,
                useExternalEditor,
                externalEditorPath,
                qdlEditors,
                enableLibrarySupport,
                assertionsOn,
                saveDir,
                allowOverwriteBaseFunctions,
                libLoader,
                false,
                logo,
                WS_TERMINAL_TYPE_TEXT,
                null); // don't let anyone start in ANSI mode on the server since it will screw up logging.
        if (serverScripts != null && !serverScripts.isEmpty()) {
            this.serverScripts = serverScripts;
        }
        this.skipBadModulesOnLoad = skipBadModulesOnLoad;
    }

    public boolean isSkipBadModulesOnLoad() {
        return skipBadModulesOnLoad;
    }

    public void setSkipBadModulesOnLoad(boolean skipBadModulesOnLoad) {
        this.skipBadModulesOnLoad = skipBadModulesOnLoad;
    }

    boolean skipBadModulesOnLoad = false;
    public boolean hasServerScripts(){
        return serverScripts != null && !serverScripts.isEmpty();
    }
    public ScriptSet getServerScripts() {
        return serverScripts;
    }

    public void setServerScripts(ScriptSet serverScripts) {
        this.serverScripts = serverScripts;
    }

    ScriptSet serverScripts = null;

}
