package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.TrivialUsernameTransformer;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.servlet.mail.ServletMailUtilProvider;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.delegation.common.servlet.DBConfigLoader;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.transactions.TransactionMemoryStore;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.api.ClientApprovalProvider;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.OA4MPServiceTransaction;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.api.admin.permissions.MultiDSPermissionStoreProvider;
import org.oa4mp.server.api.admin.permissions.PermissionStoreProviders;
import org.oa4mp.server.api.admin.transactions.*;
import org.oa4mp.server.api.storage.MultiDSClientApprovalStoreProvider;
import org.oa4mp.server.api.storage.MultiDSClientStoreProvider;
import org.oa4mp.server.api.storage.filestore.DSFSClientApprovalStoreProvider;
import org.oa4mp.server.api.storage.sql.provider.DSSQLClientApprovalStoreProvider;
import org.oa4mp.server.api.util.AbstractCLIApprover;
import org.oa4mp.server.api.util.ClientApprovalMemoryStore;
import org.oa4mp.server.api.util.ClientApproverConverter;

import javax.inject.Provider;
import java.io.File;
import java.net.URI;
import java.util.List;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstAttribute;
import static org.oa4mp.server.api.util.AbstractCLIApprover.POLLING_DIRECTORY;
import static org.oa4mp.server.api.util.AbstractCLIApprover.POLLING_INTERVAL;

/**
 * All servers configuration loaders should extend this.
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/12 at  1:18 PM
 */
public abstract class AbstractConfigurationLoader<T extends ServiceEnvironmentImpl> extends DBConfigLoader<T> implements ConfigurationLoaderInterface {

    protected MultiDSClientStoreProvider csp;
    protected MultiDSClientApprovalStoreProvider casp;
    protected MailUtilProvider mup = null;
    protected MultiDSPermissionStoreProvider mpp;
    protected ServiceEnvironmentImpl.MessagesProvider messagesProvider = null;

    /**
     * Get the value from the configuration node as a boolean. This returns the default value if
     * no such configuration value. or if it does not parse to something reasonable.
     * @param sn
     * @param tagName
     * @param defaultValue
     * @return
     */
    boolean getCfgBoolean(ConfigurationNode sn, String tagName, boolean defaultValue) {
        String x = getFirstAttribute(sn, tagName);
        if (x == null || x.length() == 0) return defaultValue;
        x = x.trim().toLowerCase();
        if("true".equals(x) || "on".equals(x)) {return true;}
        if("false".equals(x.trim()) || "off".equals(x)) {return false;}
        return defaultValue;
    }


    public AuthorizationServletConfig getAuthorizationServletConfig() {
        if (authorizationServletConfig == null) {
            List kids = cn.getChildren(OA4MPConfigTags.AUTHORIZATION_SERVLET);
            String headFieldName = null;
            boolean requiredHeader = false;
            boolean useHeader = false;
            boolean showLogon = true;
            boolean verifyUsername = true;
            boolean returnDnAsUsername = false;
            boolean convertDNToGlobusID = false;
            String authorizationURI = null;
            if (!kids.isEmpty()) {
                ConfigurationNode sn = (ConfigurationNode) kids.get(0);
                try {
                    boolean useProxy =getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_USE_PROXY, useHeader);
                    // implicitly uses the fact that null (so missing parameter) parses to false.
                    // If the useHeader tag is missing, then this is effectively false.
                    useHeader = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_HEADER_USE, useHeader);
                    if(useProxy){
                        String cfgFile = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_PROXY_CONFIG_FILE);
                        if(StringUtils.isTrivial(cfgFile)){
                            throw new IllegalArgumentException("Missing config file for the authorization proxy.");
                        }
                        File f = new File(cfgFile);
                        // check that this works before we load the configuration
                        if(!f.exists()){
                             throw new IllegalArgumentException("The file \"" + cfgFile + "\" does not exist. Check your path.");
                        }
                        if(!f.isFile()){
                            throw new IllegalArgumentException("\"" + cfgFile + "\" is not a file.");
                        }
                        if(!f.canRead()){
                            throw new IllegalArgumentException("The file \"" + cfgFile + "\" cannot be read. Check your permissions");
                        }
                        String cfgName = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_PROXY_CONFIG_NAME);
                        boolean localDFConsent = getCfgBoolean(sn,
                                OA4MPConfigTags.AUTHORIZATION_SERVLET_PROXY_DF_LOCAL_CONSENT_REQUIRED,
                                false);

                        // A missing config file is bad. However, if there is exactly one configuration in the file
                        // it does not need to be named, so the cfgName can be omitted.
                      authorizationServletConfig = new AuthorizationServletConfig(cfgFile, cfgName==null?"":cfgName, localDFConsent);
                      // Grab any authz URI or the discovery page does not get set right!
                        authorizationURI = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_URI);
                        if(authorizationURI != null){
                            authorizationServletConfig.authorizationURI = authorizationURI;
                        }

                    }else {
                        authorizationURI = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_URI);
                        if (useHeader) {
                            requiredHeader = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_HEADER_REQUIRE, requiredHeader);
                            headFieldName = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_HEADER_FIELD_NAME);
                            returnDnAsUsername = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_RETURN_DN_AS_USERNAME, returnDnAsUsername);
                            showLogon = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_SHOW_LOGON, showLogon);
                            verifyUsername = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_VERIFY_USERNAME, verifyUsername);
                            convertDNToGlobusID = getCfgBoolean(sn, OA4MPConfigTags.CONVERT_DN_TO_GLOBUS_ID, convertDNToGlobusID);
                        }
                        // Fall through. If  useHeader is true, then all the above values will be set.
                        // Otherwise, the previous defaults will be used.
                        authorizationServletConfig = new AuthorizationServletConfig(
                                authorizationURI,
                                useHeader,
                                requiredHeader,
                                headFieldName,
                                returnDnAsUsername,
                                showLogon,
                                verifyUsername,
                                convertDNToGlobusID);
                    }
                } catch (Throwable t) {
                    info("Error loading authorization configuration. Disabling use of headers");
                }
            }


        }
        return authorizationServletConfig;
    }

    /**
     * This has things that need to be executed before other code, e.g. setting up schemes for creating identifiers.
     *
     * @throws Exception
     */
    protected void initialize() {
        String scheme = Configurations.getFirstAttribute(cn, OA4MPConfigTags.ID_SCHEME);
        if (scheme != null && !scheme.isEmpty()) {
            IdentifierProvider.setScheme(scheme);
        }
        // scheme specific part
        String spp = Configurations.getFirstAttribute(cn, OA4MPConfigTags.ID_SPP);
        if (spp != null) {
            // If this is omitted in the configuration, then a null value results, so use the default.
            // It is possible to suppress this component by passing in an empty string.
            IdentifierProvider.setSchemeSpecificPart(spp);
        }
        DebugUtil.setInstance(getDebugger());
        myLogger.setClassName("oa4mp"); // sets the default logger name, sctually.
    }

    protected AuthorizationServletConfig authorizationServletConfig;

    public AbstractConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
        // this.cn = node;
        String x = Configurations.getFirstAttribute(cn, OA4MPConfigTags.DISABLE_DEFAULT_STORES);
        if (x != null) {
            isDefaultStoreDisabled(Boolean.parseBoolean(x));
        }

    }


    public AbstractConfigurationLoader(ConfigurationNode node) {
        this(node, null);
    }


    /**
     * Returns the polling directory and polling interval (resp. a file and a long, so they come
     * back as objects). This can be called independently of the rest of the bootstrap.
     *
     * @return
     */
    public Object[] loadPolling() {
        File pollingDir = null;
        Long pollingInt = 1000L; //default
        String pd = getFirstAttribute(cn, POLLING_DIRECTORY);
        String pi = getFirstAttribute(cn, POLLING_INTERVAL);
        if (pd != null && 0 < pd.length()) {
            pollingDir = new File(pd);
            if (!pollingDir.exists()) {
                info("WARNING: the given polling directory \"" + pd + "\" does not exist. Polling disabled.");
                pollingDir = null;
            } else {
                if (pollingDir.isDirectory()) {
                    info("polling directory set to \"" + pollingDir.getAbsolutePath() + "\"");
                } else {
                    pollingDir = pollingDir.getParentFile();
                    info("WARNING: the given polling directory \"" + pd + "\" does not exist. Polling set to " + pollingDir.getAbsolutePath());
                }
            }
            if (pollingDir != null && pi != null) {
                try {
                    pollingInt = Long.parseLong(pi);
                    info("Polling interval set to " + pollingInt + " ms.");
                } catch (Throwable t) {
                    // do nothing, if un-interpretable, just use default
                    info("WARNING: the polling interval of \"" + pi + "\" could not be interpreted. Using default.");
                }
            }
        } else {
            info("No polling configured.");
        }
        if (pollingDir == null) {
            return null;
        }
        return new Object[]{pollingDir, pollingInt};
    }

    protected Provider<TransactionStore> tsp;

    protected Provider<TransactionStore> getTSP() {
        if (tsp == null) {
            final DSTransactionProvider tp = new DSTransactionProvider<OA4MPServiceTransaction>();
            TransactionConverter<OA4MPServiceTransaction> tc = new TransactionConverter(tp,
                    getTokenForgeProvider().get(),
                    (ClientStore<? extends Client>) getCSP().get());

            MultiDSTransactionStoreProvider storeProvider = new MultiDSTransactionStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(), tp);
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                    getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                    getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                    getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(new DSSQLTransactionStoreProvider(cn,
                    getDerbyConnectionPoolProvider(),
                    OA4MPConfigTags.DERBY_STORE,
                    getCSP(),
                    tp,
                    getTokenForgeProvider(),
                    tc));
            storeProvider.addListener(new DSFSTransactionStoreProvider(cn, tp, getTokenForgeProvider(), tc));
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
                    return new TransactionMemoryStore(tp);
                }
            });
            tsp = storeProvider;
        }
        return tsp;
    }


    protected abstract MultiDSClientStoreProvider getCSP();

    protected MultiDSPermissionStoreProvider getMpp() {
        if (mpp == null) {
            mpp = new MultiDSPermissionStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(),
                    null, null, PermissionStoreProviders.getPermissionProvider());
            mpp.addListener(PermissionStoreProviders.getM(cn));
            mpp.addListener(PermissionStoreProviders.getFSP(cn));
            mpp.addListener(PermissionStoreProviders.getMariaPS(cn, getMariaDBConnectionPoolProvider()));
            mpp.addListener(PermissionStoreProviders.getPostgresPS(cn, getPgConnectionPoolProvider()));
            mpp.addListener(PermissionStoreProviders.getDerbyPS(cn, getDerbyConnectionPoolProvider()));
            mpp.addListener(PermissionStoreProviders.getMysqlPS(cn, getMySQLConnectionPoolProvider()));
        }
        return mpp;
    }

    protected MultiDSClientApprovalStoreProvider getCASP() {
        if (casp == null) {
            casp = new MultiDSClientApprovalStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            final ClientApprovalProvider caProvider = new ClientApprovalProvider();
            final ClientApproverConverter cp = new ClientApproverConverter(caProvider);
            casp.addListener(new DSFSClientApprovalStoreProvider(cn, cp));
            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getMySQLConnectionPoolProvider(), OA4MPConfigTags.MYSQL_STORE, cp));
            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getMariaDBConnectionPoolProvider(), OA4MPConfigTags.MARIADB_STORE, cp));

            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getPgConnectionPoolProvider(), OA4MPConfigTags.POSTGRESQL_STORE, cp));
            casp.addListener(new DSSQLClientApprovalStoreProvider(cn, getDerbyConnectionPoolProvider(), OA4MPConfigTags.DERBY_STORE, cp));

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
                    return new ClientApprovalMemoryStore(caProvider, cp);
                }
            });
        }
        return casp;
    }


    protected MailUtilProvider getMailUtilProvider() {
        if (mup == null) {
            if (0 < cn.getChildrenCount(OA4MPConfigTags.MAIL)) {
                mup = new ServletMailUtilProvider(((ConfigurationNode) cn.getChildren(OA4MPConfigTags.MAIL).get(0)));
            } else {
                mup = new ServletMailUtilProvider();
            }
        }
        return mup;
    }

    protected ServiceEnvironmentImpl.MessagesProvider getMP() {
        if (messagesProvider == null) {
            if (0 < cn.getChildrenCount(OA4MPConfigTags.MESSAGES)) {
                messagesProvider = new ServiceEnvironmentImpl.MessagesProvider(((ConfigurationNode) cn.getChildren(OA4MPConfigTags.MESSAGES).get(0)));
            }
        }
        return messagesProvider;
    }

    @Override
    public T createInstance() {
        initialize();
        return (T) new ServiceEnvironmentImpl(loggerProvider.get(),
              //  getMyProxyFacadeProvider(),
                getTransactionStoreProvider(),
                getClientStoreProvider(),
                getMaxAllowedNewClientRequests(),
                getClientApprovalStoreProvider(),
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
                getMpp());
    }

    protected boolean getPingable() {
        boolean isPingable = true; //default
        try {
            String y = Configurations.getFirstAttribute(cn, OA4MPConfigTags.PINGABLE);
            if (y == null || y.length() == 0) {
                // use the default
            } else {
                isPingable = Boolean.parseBoolean(y);
            }
        } catch (Throwable t) {
            warn("Could not parse " + OA4MPConfigTags.PINGABLE + " property. Using default of " + isPingable);
        }
        if (isPingable) {
            info("ping enabled");
        } else {
            info("ping disabled");
        }
        return isPingable;
    }

    int maxAllowedNewClientRequests = -1;

    public int getMaxAllowedNewClientRequests() {
        if (maxAllowedNewClientRequests < 0) {
            maxAllowedNewClientRequests = 100; //default
            String x = Configurations.getFirstAttribute(cn, OA4MPConfigTags.MAX_ALLOWED_NEW_CLIENT_REQUESTS);
            if (x != null) {
                try {
                    maxAllowedNewClientRequests = Integer.parseInt(x);
                } catch (Throwable t) {
                    // do zilch. Just use default if not readable.
                }
            }
        }
        return maxAllowedNewClientRequests;
    }


    URI address;

    public URI getServiceAddress() {
        if (address == null) {
            // The OAuth library requires this property but does not seem to use it. Omitting it though causes
            // failures though (null pointer exceptions), so it must be a valid address.

            String x = Configurations.getFirstAttribute(cn, OA4MPConfigTags.SERVICE_ADDRESS);
            if (x == null) {
                warn("Warning: service address set to default. Do you need an \"address\" attribute in your service config. tag?");
                x = "http://localhost"; // MUST be a valid URI or this will fail later.
            }
            address = URI.create(x);
        }
        return address;
    }

    public UsernameTransformer getUsernameTransformer() {
        return new TrivialUsernameTransformer();
    }


    @Override
    public T load() {
        info("loading configuration.");
        ServiceEnvironmentImpl se2 = createInstance();
        // now peel off the service address

        se2.setServiceAddress(getServiceAddress());
        getDebugger();
        se2.setDebugOn(DebugUtil.isEnabled());
        se2.info("Debugging is " + (se2.isDebugOn() ? "on" : "off"));

        // part 2. This is done after main config load.
        Object[] polling = loadPolling();


        if (polling != null && 0<(long)polling[1]) {
            // only start polling if the polling interval is positive.
            info("Loading polling for " + polling[0]);
            AbstractCLIApprover.ClientApprovalThread cat = new AbstractCLIApprover.ClientApprovalThread(myLogger, se2, (File) polling[0], (Long) polling[1]);
            se2.setClientApprovalThread(cat);
        }



        return (T) se2;
    }
}
