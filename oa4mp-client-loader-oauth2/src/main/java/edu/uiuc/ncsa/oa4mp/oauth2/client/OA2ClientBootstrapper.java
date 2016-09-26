package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Initialization;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/5/13 at  2:40 PM
 */
public class OA2ClientBootstrapper extends AbstractClientBootstrapper{
    public static final String OA2_CLIENT_CONFIG_FILE_KEY= "oa4mp:oauth2.client.config.file";
    public static final String OA2_CLIENT_CONFIG_NAME_KEY= "oa4mp:oauth2.client.config.name";
    @Override
    public String getOa4mpConfigFileKey() {
        return OA2_CLIENT_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return OA2_CLIENT_CONFIG_NAME_KEY;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new OA2ClientLoader(node);
    }

    @Override
    public Initialization getInitialization() {
        return new OA2ClientServletInitializer();
    }
}
