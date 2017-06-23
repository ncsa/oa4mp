package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap.LDAPStoreProviderUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap.MultiLDAPStoreProvider;
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


    MultiLDAPStoreProvider mldap = null;

    protected MultiLDAPStoreProvider getMLDAP() {
        if (mldap == null) {
            mldap = new MultiLDAPStoreProvider(cn, isDefaultStoreDisabled(), (MyLoggingFacade) loggerProvider.get(), null, null, LDAPStoreProviderUtil.getLdapEntryProvider());
            mldap.addListener(LDAPStoreProviderUtil.getM(cn));
            mldap.addListener(LDAPStoreProviderUtil.getFSP(cn));
            mldap.addListener(LDAPStoreProviderUtil.getMariaDB(cn, getMariaDBConnectionPoolProvider()));
            mldap.addListener(LDAPStoreProviderUtil.getMysql(cn, getMySQLConnectionPoolProvider()));
            mldap.addListener(LDAPStoreProviderUtil.getPG(cn, getPgConnectionPoolProvider()));
        }
        return mldap;
    }

    @Override
    public ServiceEnvironmentImpl createInstance() {
        try {
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
                    getScopeHandler(),
                    getLdapConfiguration(),
                    isRefreshTokenEnabled(),
                    isTwoFactorSupportEnabled(),
                    getMaxClientRefreshTokenLifetime(),
                    getMLDAP(),
                    getJSONWebKeys(),
                    getIssuer());

        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }
}
