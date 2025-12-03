package org.oa4mp.server.qdl;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.util.cli.IOInterface;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;
import org.qdl_lang.config.QDLConfigurationConstants;
import org.qdl_lang.state.LibLoader;
import org.qdl_lang.workspace.WorkspaceCommands;

import java.util.ArrayList;
import java.util.List;

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
            CFNode node = CFXMLConfigurations.findConfiguration(inputLine.getNextArgFor(QDLConfigurationConstants.CONFIG_FILE_FLAG),  OA4MPConfigTags.COMPONENT, cfgName);
            OA2CFConfigurationLoader sourceLoader = new OA2CFConfigurationLoader<>(node);
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

    protected List<LibLoader> loaders;

    @Override
    public List<LibLoader> getLibLoaders() {
        if (loaders == null) {
            loaders = new ArrayList<>();
            // Fix https://github.com/ncsa/oa4mp/issues/207
            loaders.add(new OA2LibLoader2());
        }
        return loaders;
    }
}
