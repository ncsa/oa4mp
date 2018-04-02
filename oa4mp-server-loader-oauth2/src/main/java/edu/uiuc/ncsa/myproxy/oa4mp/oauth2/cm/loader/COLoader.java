package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/17/16 at  10:40 AM
 */
public class COLoader extends OA2ConfigurationLoader {
    public COLoader(ConfigurationNode node) {
        super(node);
    }

    public COLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }




    @Override
    public ServiceEnvironmentImpl createInstance() {
        try {
            initialize();
            return new COSE((MyLoggingFacade) loggerProvider.get(),
                    getTransactionStoreProvider(),
                    getClientStoreProvider(),
                    getMaxAllowedNewClientRequests(),
                    getRTLifetime(),
                    getClientApprovalStoreProvider(),
                    getMyProxyFacadeProvider(),
                    getMailUtilProvider(),
                    getMP(),
                    getAGIProvider(),
                    getATIProvider(),
                    getPAIProvider(),
                    getTokenForgeProvider(),
                    getConstants(),
                    getAuthorizationServletConfig(),
                    getUsernameTransformer(),
                    getPingable(),
                    getMpp(),
                    getMacp(),
                    getClientSecretLength(),
                    getScopes(),
                    getClaimSource(),
                    getLdapConfiguration(),
                    isRefreshTokenEnabled(),
                    isTwoFactorSupportEnabled(),
                    getMaxClientRefreshTokenLifetime(),
                    getMLDAP(),
                    getJSONWebKeys(),
                    getIssuer(),
                    isUtilServerEnabled());

        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }
}
