package org.oa4mp.server.qdl;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.qdl_lang.config.QDLConfigurationConstants;
import org.qdl_lang.workspace.WorkspaceCommands;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.util.cli.IOInterface;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/21/24 at  11:20 AM
 */
public class OA4MPQDLWorkspaceCommands extends WorkspaceCommands {
    public OA4MPQDLWorkspaceCommands() {
    }

    public OA4MPQDLWorkspaceCommands(IOInterface ioInterface) {
        super(ioInterface);
    }

    @Override
    public void loadQE(InputLine inputLine, String cfgName) throws Throwable {
        try {
            super.loadQE(inputLine, cfgName);
        } catch (MyConfigurationException mcx) {
             // try to process it as a server config
            // https://github.com/ncsa/oa4mp/issues/196
            ConfigurationNode node = XMLConfigUtil.findConfiguration(inputLine.getNextArgFor(QDLConfigurationConstants.CONFIG_FILE_FLAG), cfgName, OA4MPConfigTags.COMPONENT);
            OA2ConfigurationLoader sourceLoader = new OA2ConfigurationLoader<>(node);
            OA2SE sourceSE = (OA2SE) sourceLoader.load();
             setQdlEnvironment(sourceSE.getQDLEnvironment());
        }
    }

    @Override
    public WorkspaceCommands newInstance() {
        return new OA4MPQDLWorkspaceCommands();
    }

    @Override
    public WorkspaceCommands newInstance(IOInterface ioInterface) {
        return new OA4MPQDLWorkspaceCommands(ioInterface);
    }
}
