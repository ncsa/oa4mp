package edu.uiuc.ncsa.myproxy.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/7/16 at  11:32 AM
 */
public class OIDC2FAConfigLoader extends OA2ConfigurationLoader{
    public OIDC2FAConfigLoader(ConfigurationNode node) {
        super(node);
    }

    public OIDC2FAConfigLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public ScopeHandler getScopeHandler() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        return super.getScopeHandler();
    }
}
