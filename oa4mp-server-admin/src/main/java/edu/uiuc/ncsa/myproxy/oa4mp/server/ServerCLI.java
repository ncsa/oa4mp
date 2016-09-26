package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.oa4mp.loader.OA4MPConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.storage.cli.StoreUtil;

/**
 * A few top-level items any server CLIDriver needs to attend to. All utilities should
 * extend this.
 * <p>Created by Jeff Gaynor<br>
 * on 5/16/13 at  3:27 PM
 */
public abstract class ServerCLI extends StoreUtil{
    @Override
    public String getComponentName() {
        return OA4MPConfigTags.COMPONENT;
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() throws Exception {
        return new OA4MPConfigurationLoader(getConfigurationNode());
    }


}
