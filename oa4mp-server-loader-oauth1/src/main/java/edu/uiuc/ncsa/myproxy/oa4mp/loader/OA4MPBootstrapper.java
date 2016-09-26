package edu.uiuc.ncsa.myproxy.oa4mp.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.OA4MPServletInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Initialization;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/21/12 at  11:09 AM
 */
public class OA4MPBootstrapper extends AbstractBootstrapper {

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new OA4MPConfigurationLoader(node);
    }

    Initialization initialization;

    @Override
    public Initialization getInitialization() {
        if (initialization == null) {
            initialization = new OA4MPServletInitializer();
        }
        return initialization;
    }
}
