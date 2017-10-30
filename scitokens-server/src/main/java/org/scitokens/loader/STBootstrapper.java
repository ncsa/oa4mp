package org.scitokens.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ServletInitializer;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Initialization;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  1:06 PM
 */
public class STBootstrapper extends OA2Bootstrapper {
  /*  public static final String ST_CONFIG_FILE_KEY = "oa4mp:scitokens.server.config.file";
    public static final String ST_CONFIG_NAME_KEY = "oa4mp:scitokens.server.config.name";

    @Override
    public String getOa4mpConfigFileKey() {
        return ST_CONFIG_FILE_KEY;
    }

    @Override
    public String getOa4mpConfigNameKey() {
        return ST_CONFIG_NAME_KEY;
    }
*/
    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new STLoader(node);
    }

    @Override
    public Initialization getInitialization() {
        return new OA2ServletInitializer();
    }
}
