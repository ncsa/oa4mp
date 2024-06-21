package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.qdl.config.QDLConfigurationConstants;
import edu.uiuc.ncsa.qdl.workspace.WorkspaceCommands;
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
