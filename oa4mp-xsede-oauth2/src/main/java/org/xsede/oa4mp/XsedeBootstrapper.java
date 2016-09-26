package org.xsede.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import org.apache.commons.configuration.tree.ConfigurationNode;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import org.xsede.oa4mp.XsedeConfigurationLoader;

public class XsedeBootstrapper extends OA2Bootstrapper {
    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new XsedeConfigurationLoader(node);
    }
}
