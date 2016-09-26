package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Initialization;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/13 at  3:53 PM
 */
public class OA2Bootstrapper extends AbstractBootstrapper {
    public static final String OA2_CONFIG_FILE_KEY = "oa4mp:oauth2.server.config.file";
    public static final String OA2_CONFIG_NAME_KEY = "oa4mp:oauth2.server.config.name";

    @Override
    public String getOa4mpConfigFileKey() {
        return OA2_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return OA2_CONFIG_NAME_KEY;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new OA2ConfigurationLoader(node);
    }

    @Override
    public Initialization getInitialization() {
        return new OA2ServletInitializer();
    }
}
