package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Initialization;
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

    @Override
    public Initialization getInitialization() {
        return new COInitializer();
    }
}
