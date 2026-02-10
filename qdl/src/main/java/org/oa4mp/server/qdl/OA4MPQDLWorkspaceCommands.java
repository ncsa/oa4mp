package org.oa4mp.server.qdl;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.cli.IOInterface;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
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

    public static final String OA4MP_CONFIG_FILE_FLAG = "-oa4mp:cfg";
    public static final String OA4MP_CONFIG_NAME = "-oa4mp:cfg_name";
    @Override
    public void loadQE(InputLine inputLine, String cfgName) throws Throwable {
        try {
            OA2SE oa2SE = null;
            super.loadQE(inputLine, cfgName);
            if(inputLine.hasArg(OA4MP_CONFIG_FILE_FLAG) && inputLine.hasArg(OA4MP_CONFIG_NAME)){
                CFNode node =
                        CFXMLConfigurations.findConfiguration(inputLine.getNextArgFor(OA4MP_CONFIG_FILE_FLAG), OA4MPConfigTags.COMPONENT, inputLine.getNextArgFor(OA4MP_CONFIG_NAME));
                ConfigurationLoader<? extends AbstractEnvironment> loader = new OA2CFConfigurationLoader<>(node, getLogger());
                oa2SE = (OA2SE) loader.load();
            }
            // Fix https://github.com/ncsa/oa4mp/issues/285

            OA2State oa2State = new OA2State(getState(),false, new JSONWebKeys("dummy"));
            oa2State.setOa2se(oa2SE);
            setState(oa2State);
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
