package org.xsede.oa4mp;

import java.util.Arrays;

import org.xsede.oa4mp.XsedeScopeHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;

import edu.uiuc.ncsa.security.core.configuration.Configurations;

import java.lang.ClassNotFoundException;
import java.lang.IllegalAccessException;
import java.lang.InstantiationException;

import org.apache.commons.configuration.tree.ConfigurationNode;

public class XsedeConfigurationLoader<T extends OA2SE> extends OA2ConfigurationLoader<T> {
    public XsedeConfigurationLoader(ConfigurationNode node) {
        super(node);
    }
    public XsedeConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public ScopeHandler getScopeHandler() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (0 < cn.getChildrenCount("xsedeApi".toString())) {

            ConfigurationNode node = Configurations.getFirstNode(cn, "xsedeApi".toString());
            ConfigurationNode username = Configurations.getFirstNode(node, "username".toString());
            ConfigurationNode password = Configurations.getFirstNode(node, "password".toString());
            ConfigurationNode apikey = Configurations.getFirstNode(node, "api-key".toString());
            ConfigurationNode apihash = Configurations.getFirstNode(node, "api-hash".toString());
            ConfigurationNode apiurl = Configurations.getFirstNode(node, "api-url".toString());
            ConfigurationNode apiresource = Configurations.getFirstNode(node, "api-resource".toString());
            if (apikey != null && apihash != null && apiurl != null && apiresource != null) {
                scopeHandler = new XsedeScopeHandler(loggerProvider.get(),
                               apikey.getValue().toString(),
                               apihash.getValue().toString(),
                               apiurl.getValue().toString(),
                               apiresource.getValue().toString());
            } else if (username != null && password != null) {
                scopeHandler = new XsedeScopeHandler(username.getValue().toString(),
                               password.getValue().toString(), loggerProvider.get());
            } else
                throw new InstantiationException("Couldn't find XUP API authentication credentials");

            // scopeHandler.setScopes(Arrays.asList("xsede"));
            scopeHandler.setScopes(getScopes()); // this is a complete list of scopes from the configuration file.
            return scopeHandler;
        } else
            throw new InstantiationException("Couldn't find an XUP API authentication credential");
    }
}
