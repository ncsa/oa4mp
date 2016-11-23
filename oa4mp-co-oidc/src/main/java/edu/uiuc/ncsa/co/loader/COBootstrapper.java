package edu.uiuc.ncsa.co.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  4:14 PM
 */
public class COBootstrapper extends OA2Bootstrapper {
    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new COLoader(node);
    }

}
