package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.LDAPScopeHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSTransactionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSSQLClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientApprovalMemoryStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.*;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;
import java.util.Collection;
import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.TRANSACTION_ID;
import static edu.uiuc.ncsa.security.core.configuration.Configurations.*;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigTags.*;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/23/13 at  1:50 PM
 */
public class OA2ConfigurationLoader<T extends ServiceEnvironmentImpl> extends AbstractConfigurationLoader<T> {
    /**
     * Default is 15 days. Internally the refresh lifetime (as all date-ish things) are in milliseconds
     * though the configuration file is assumed to be in seconds.
     */
    public long REFRESH_TOKEN_LIFETIME_DEFAULT = 15 * 24 * 3600 * 1000L;
    public int CLIENT_SECRET_LENGTH_DEFAULT = 258; //This is divisible by 3 and greater than 256, so when it is base64 encoded there will be no extra characters.

    public OA2ConfigurationLoader(ConfigurationNode node) {
        super(node);
    }

    public OA2ConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public T createInstance() {
        try {
            T se = (T) new OA2SE(loggerProvider.get(),
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
                    getJSONWebKeys());
            if (getScopeHandler() instanceof BasicScopeHandler) {
                ((BasicScopeHandler) getScopeHandler()).setOa2SE((OA2SE) se);
            }
            return se;
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }

    HashMap<String, String> constants;

    @Override
    public HashMap<String, String> getConstants() {
        if (constants == null) {
            constants = new HashMap<String, String>();
            // OAuth 1.0a callback constant. This is used to as a key for http request parameters
            constants.put(ServiceConstantKeys.CALLBACK_URI_KEY, REDIRECT_URI);
            constants.put(ServiceConstantKeys.TOKEN_KEY, AUTHORIZATION_CODE);
            constants.put(ServiceConstantKeys.FORM_ENCODING_KEY, FORM_ENCODING);
            constants.put(ServiceConstantKeys.CERT_REQUEST_KEY, CERT_REQ);
            constants.put(ServiceConstantKeys.CERT_LIFETIME_KEY, CERT_LIFETIME);
            constants.put(ServiceConstantKeys.CONSUMER_KEY, OA2Constants.CLIENT_ID);
        }
        return constants;
    }

    protected JSONWebKeys getJSONWebKeys() {
        ConfigurationNode node = getFirstNode(cn, "JSONWebKey");
        if(node == null){
            warn("Error: No signing keys in the configuration file. Signing is not available");
            //throw new IllegalStateException();
            return new JSONWebKeys(null);
        }
        String json = getNodeValue(node, "json", null); // if the whole thing is included
        JSONWebKeys keys = null;
        try {
            if (json != null) {
                keys = JSONWebKeyUtil.fromJSON(json);
            }
            String path = getNodeValue(node, "path", null); // points to a file that contains it all
            if (path != null) {
                keys = JSONWebKeyUtil.fromJSON(new File(path));
            }
        } catch (Throwable t) {
            throw new GeneralException("Error reading signing keys", t);
        }

        if(keys == null){
            throw new IllegalStateException("Error: Could not load signing keys");
        }
        keys.setDefaultKeyID(getFirstAttribute(node, "defaultKeyID"));
        return keys;
    }

    @Override
    public Provider<AGIssuer> getAGIProvider() {
        if (agip == null) {
            return new Provider<AGIssuer>() {
                @Override
                public AGIssuer get() {
                    return new AGI2(getTokenForgeProvider().get(), getServiceAddress());
                }
            };
        }
        return agip;
    }

    Provider<AGIssuer> agip = null;

    @Override
    public Provider<ClientApprovalStore> getClientApprovalStoreProvider() {
        return getCASP();
    }

    @Override
    public Provider<ClientStore> getClientStoreProvider() {
        return getCSP();
    }

    @Override
    protected MultiDSClientApprovalStoreProvider getCASP() {
        if (casp == null) {
            casp = new MultiDSClientApprovalStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            final ClientApprovalProvider caProvider = new ClientApprovalProvider();
            ClientApprovalKeys caKeys = new ClientApprovalKeys();
            caKeys.identifier("client_id");
            ClientApproverConverter cp = new ClientApproverConverter(caKeys, caProvider);
            casp.addListener(new DSFSClientApprovalStoreProvider(cn, cp));
            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getMySQLConnectionPoolProvider(), OA4MPConfigTags.MYSQL_STORE, cp));
            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getMariaDBConnectionPoolProvider(), OA4MPConfigTags.MARIADB_STORE, cp));
            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getPgConnectionPoolProvider(), OA4MPConfigTags.POSTGRESQL_STORE, cp));

            casp.addListener(new TypedProvider<ClientApprovalStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.CLIENT_APPROVAL_STORE) {

                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public ClientApprovalStore get() {
                    return new ClientApprovalMemoryStore(caProvider);
                }
            });
        }
        return casp;
    }

    public class OA4MP2TProvider extends DSTransactionProvider<OA2ServiceTransaction> {
        public OA4MP2TProvider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public OA2ServiceTransaction get(boolean createNewIdentifier) {
            return new OA2ServiceTransaction(createNewId(createNewIdentifier));
        }
    }

    long rtLifetime = -1L;

    protected long getRTLifetime() {
        if (rtLifetime < 0) {
            String x = getFirstAttribute(cn, REFRESH_TOKEN_LIFETIME);
            // Fixes OAUTH-214
            if (x == null || x.length() == 0) {
                rtLifetime = REFRESH_TOKEN_LIFETIME_DEFAULT;
            } else {
                try {
                    rtLifetime = Long.parseLong(x) * 1000; // The configuration file has this in seconds. Internally this is ms.
                } catch (Throwable t) {
                    rtLifetime = REFRESH_TOKEN_LIFETIME_DEFAULT;
                }
            }
        }
        return rtLifetime;

    }

    long maxClientRefreshTokenLifetime = -1L;

    protected long getMaxClientRefreshTokenLifetime() {
        if (maxClientRefreshTokenLifetime < 0) {
            String x = getFirstAttribute(cn, MAX_CLIENT_REFRESH_TOKEN_LIFETIME);
            // Fixes OAUTH-214
            if (x == null || x.length() == 0) {
                maxClientRefreshTokenLifetime = 13 * 30 * 24 * 3600 * 1000L; // default of 13 months.
            } else {
                try {
                    maxClientRefreshTokenLifetime = Long.parseLong(x) * 1000; // The configuration file has this in seconds. Internally this is ms.
                } catch (Throwable t) {
                    maxClientRefreshTokenLifetime = 13 * 30 * 24 * 3600 * 1000L; // default of 13 months.
                }
            }
        }
        return maxClientRefreshTokenLifetime;
    }

    public boolean isRefreshTokenEnabled() {
        if (refreshTokenEnabled == null) {
            String x = getFirstAttribute(cn, REFRESH_TOKEN_ENABLED);
            if (x == null) {
                refreshTokenEnabled = Boolean.FALSE;
            } else {
                try {
                    refreshTokenEnabled = Boolean.valueOf(x);
                } catch (Throwable t) {
                    info("Could not parse refresh token enabled attribute. Setting default to false.");
                    refreshTokenEnabled = Boolean.FALSE;
                }
            }
        }
        return refreshTokenEnabled;
    }

    Boolean twoFactorSupportEnabled = null;

    public boolean isTwoFactorSupportEnabled() {
        if (twoFactorSupportEnabled == null) {
            String x = getFirstAttribute(cn, ENABLE_TWO_FACTOR_SUPPORT);
            if (x == null) {
                twoFactorSupportEnabled = Boolean.FALSE;
            } else {
                try {
                    twoFactorSupportEnabled = Boolean.valueOf(x);
                } catch (Throwable t) {
                    info("Could not parse two factor enabled attribute. Setting default to false.");
                    twoFactorSupportEnabled = Boolean.FALSE;
                }
            }

        }
        return twoFactorSupportEnabled;
    }

    public void setRefreshTokenEnabled(boolean refreshTokenEnabled) {
        this.refreshTokenEnabled = refreshTokenEnabled;
    }

    Boolean refreshTokenEnabled = null;
    Collection<String> scopes = null;
    protected ScopeHandler scopeHandler;

    public ScopeHandler getScopeHandler() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        DebugUtil.dbg(this, "Getting scope handler " + scopeHandler);
        if (scopeHandler == null) {
            // This gets the scopes if any and injects them into the scope handler.
            if (0 < cn.getChildrenCount(SCOPES)) {
                String scopeHandlerName = getFirstAttribute(Configurations.getFirstNode(cn, SCOPES), SCOPE_HANDLER);
                if (scopeHandlerName != null) {
                    Class<?> k = Class.forName(scopeHandlerName);
                    Object x = k.newInstance();
                    if (!(x instanceof ScopeHandler)) {
                        throw new GeneralException("The scope handler specified by the class name \"" +
                                scopeHandlerName + "\" does not extend the ScopeHandler " +
                                "interface and therefore cannot be used to handle scopes.");
                    }
                    scopeHandler = (ScopeHandler) x;
                } else {
                    info("Scope handler attribute found in configuration, but no value was found for it. Skipping custom loaded scope handling.");
                }
            }

            // no scopes element, so just use the basic handler.
            if (scopeHandler == null) {

                DebugUtil.dbg(this, "No configured Scope handler");
                if (getLdapConfiguration().isEnabled()) {
                    DebugUtil.dbg(this, "   LDAP scope handler enabled, creating default");

                    scopeHandler = new LDAPScopeHandler(getLdapConfiguration(), myLogger);
                } else {
                    DebugUtil.dbg(this, "   LDAP scope handler disabled, creating basic");
                    scopeHandler = new BasicScopeHandler();
                }
            }
            scopeHandler.setScopes(getScopes());
            DebugUtil.dbg(this, "   Actual scope handler = " + scopeHandler.getClass().getSimpleName());

        }
        return scopeHandler;
    }

    LDAPConfiguration ldapConfiguration;

    protected LDAPConfiguration getLdapConfiguration() {
        if (ldapConfiguration == null) {
            ldapConfiguration = LDAPConfigurationUtil.getLdapConfiguration(myLogger, cn);
        }
        return ldapConfiguration;

    }

    public Collection<String> getScopes() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (scopes == null) {
            scopes = OA2ConfigurationLoaderUtils.getScopes(cn);
        }
        return scopes;
    }

    public int getClientSecretLength() {
        if (clientSecretLength < 0) {
            String x = getFirstAttribute(cn, CLIENT_SECRET_LENGTH);
            if (x != null) {
                try {
                    clientSecretLength = Integer.parseInt(x);
                } catch (Throwable t) {
                    clientSecretLength = CLIENT_SECRET_LENGTH_DEFAULT;
                }
            } else {
                clientSecretLength = CLIENT_SECRET_LENGTH_DEFAULT;
            }
        }
        return clientSecretLength;
    }

    int clientSecretLength = -1; // Negative (illegal value) to trigger parsing from config file on load. Default is 258.


    public static class ST2Provider extends DSTransactionProvider<OA2ServiceTransaction> {

        public ST2Provider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public OA2ServiceTransaction get(boolean createNewIdentifier) {
            return new OA2ServiceTransaction(createNewId(createNewIdentifier));
        }
    }

    public static class OA2MultiDSClientStoreProvider extends MultiDSClientStoreProvider {
        public OA2MultiDSClientStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger) {
            super(config, disableDefaultStore, logger);
        }

        public OA2MultiDSClientStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target, IdentifiableProvider clientProvider) {
            super(config, disableDefaultStore, logger, type, target, clientProvider);
        }

        @Override
        public ClientStore getDefaultStore() {
            logger.info("Using default in memory client store");
            return new OA2ClientMemoryStore(clientProvider);
        }
    }

    @Override
    protected MultiDSClientStoreProvider getCSP() {
        if (csp == null) {
            OA2ClientConverter converter = new OA2ClientConverter(getClientProvider());
            csp = new OA2MultiDSClientStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(), null, null, getClientProvider());

            csp.addListener(new DSFSClientStoreProvider(cn, converter, getClientProvider()));
            csp.addListener(new OA2ClientSQLStoreProvider(getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    converter, getClientProvider()));
            csp.addListener(new OA2ClientSQLStoreProvider(getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    converter, getClientProvider()));
            csp.addListener(new OA2ClientSQLStoreProvider(getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    converter, getClientProvider()));
            csp.addListener(new TypedProvider<ClientStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.CLIENTS_STORE) {

                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public ClientStore get() {
                    return new OA2ClientMemoryStore(getClientProvider());
                }
            });
        }
        return csp;
    }

    protected OA2SQLTransactionStoreProvider createSQLTSP(ConfigurationNode config,
                                                          ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                                          String type,
                                                          MultiDSClientStoreProvider clientStoreProvider,
                                                          Provider<? extends OA2ServiceTransaction> tp,
                                                          Provider<TokenForge> tfp,
                                                          MapConverter converter) {
        return new OA2SQLTransactionStoreProvider(config, cpp, type, clientStoreProvider, tp, tfp, converter);
    }

    protected Provider<TransactionStore> getTSP(IdentifiableProvider tp,
                                                OA2TConverter<? extends OA2ServiceTransaction> tc) {
        if (tsp == null) {
            final IdentifiableProvider tp1 = tp; // since this is referenced in an inner class below.
            OA2MultiTypeProvider storeProvider = new OA2MultiTypeProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(), tp);
            storeProvider.addListener(createSQLTSP(cn,
                    getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(createSQLTSP(cn,
                    getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(createSQLTSP(cn,
                    getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));

            storeProvider.addListener(new OA2FSTStoreProvider(cn, tp, getTokenForgeProvider(), tc));
            storeProvider.addListener(new TypedProvider<TransactionStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.TRANSACTIONS_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public TransactionStore get() {
                    return new OA2MTStore(tp1);
                }

            });
            tsp = storeProvider;
        }
        return tsp;
    }

    @Override
    protected Provider<TransactionStore> getTSP() {
        IdentifiableProvider tp = new ST2Provider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, TRANSACTION_ID, false));
        OA2TransactionKeys keys = new OA2TransactionKeys();
        OA2TConverter<OA2ServiceTransaction> tc = new OA2TConverter<OA2ServiceTransaction>(keys, tp, getTokenForgeProvider().get(), getClientStoreProvider().get());
        return getTSP(tp, tc);
    }


    @Override
    public Provider<TransactionStore> getTransactionStoreProvider() {
        return getTSP();
    }

    @Override
    public Provider<TokenForge> getTokenForgeProvider() {
        return new Provider<TokenForge>() {
            @Override
            public TokenForge get() {
                return new OA2TokenForge(getServiceAddress().toString());
            }
        };
    }

    @Override
    public Provider<ATIssuer> getATIProvider() {
        return new Provider<ATIssuer>() {
            @Override
            public ATIssuer get() {
                return new ATI2(getTokenForgeProvider().get(), getServiceAddress());
            }
        };
    }

    @Override
    public Provider<PAIssuer> getPAIProvider() {
        return new Provider<PAIssuer>() {
            @Override
            public PAIssuer get() {
                return new PAI2(getTokenForgeProvider().get(), getServiceAddress());
            }
        };
    }


    @Override
    public IdentifiableProvider<? extends Client> getClientProvider() {
        return new OA2ClientProvider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, OA2Constants.CLIENT_ID, false));
    }

    @Override
    public String getVersionString() {
        return "OAuth 2 for MyProxy, version " + VERSION_NUMBER;
    }
}
