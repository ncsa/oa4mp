package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.MultiDSAdminClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.MultiDSPermissionStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSSQLClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientApprovalMemoryStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.TransactionMemoryStore;
import edu.uiuc.ncsa.security.servlet.TrivialUsernameTransformer;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.servlet.mail.ServletMailUtilProvider;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;
import java.net.URI;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover.POLLING_DIRECTORY;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover.POLLING_INTERVAL;
import static edu.uiuc.ncsa.security.core.configuration.Configurations.getFirstAttribute;

/**
 * All servers configuration loaders should extend this.
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/12 at  1:18 PM
 */
public abstract class AbstractConfigurationLoader<T extends ServiceEnvironmentImpl> extends MyProxyConfigurationLoader<T> implements ConfigurationLoaderInterface {

    protected MultiDSClientStoreProvider csp;
    protected MultiDSClientApprovalStoreProvider casp;
    protected MailUtilProvider mup = null;
    protected MultiDSPermissionStoreProvider mpp;
    protected MultiDSAdminClientStoreProvider macp;
    protected ServiceEnvironmentImpl.MessagesProvider messagesProvider = null;

    boolean getCfgBoolean(ConfigurationNode sn, String tagName, boolean defaultValue) {
        String x = getFirstAttribute(sn, tagName);
        if (x == null || x.length() == 0) return defaultValue;
        boolean b = defaultValue;
        try {
            b = Boolean.parseBoolean(x);
        } catch (Throwable t) {
            return defaultValue;
        }
        return b;
    }

    public AuthorizationServletConfig getAuthorizationServletConfig() {
        if (authorizationServletConfig == null) {
            List kids = cn.getChildren(OA4MPConfigTags.AUTHORIZATION_SERVLET);
            String headFieldName = null;
            boolean requiredHeader = false;
            boolean useheader = false;
            boolean showLogon = true;
            boolean verifyUsername = true;
            boolean returnDnAsUsername = false;
            boolean convertDNToGlobusID = false;
            String authorizationURI = null;
            if (!kids.isEmpty()) {
                ConfigurationNode sn = (ConfigurationNode) kids.get(0);
                try {

                    // implicitly uses the fact that null (so missing parameter) parses to false.
                    authorizationURI = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_URI);
                    useheader = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_HEADER_USE, useheader);
                    requiredHeader = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_HEADER_REQUIRE, requiredHeader);
                    headFieldName = getFirstAttribute(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_HEADER_FIELD_NAME);
                    returnDnAsUsername = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_RETURN_DN_AS_USERNAME, returnDnAsUsername);
                    showLogon = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_SHOW_LOGON, showLogon);
                    verifyUsername = getCfgBoolean(sn, OA4MPConfigTags.AUTHORIZATION_SERVLET_VERIFY_USERNAME, verifyUsername);
                    convertDNToGlobusID = getCfgBoolean(sn, OA4MPConfigTags.CONVERT_DN_TO_GLOBUS_ID, convertDNToGlobusID);
                } catch (Throwable t) {
                    info("Error loading authorization configuration. Disabling use of headers");
                }
            }
            authorizationServletConfig = new AuthorizationServletConfig(
                    authorizationURI,
                    useheader,
                    requiredHeader,
                    headFieldName,
                    returnDnAsUsername,
                    showLogon,
                    verifyUsername,
                    convertDNToGlobusID);
        }
        return authorizationServletConfig;
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

    protected MultiDSAdminClientStoreProvider getMacp(){
        if(macp == null){
              macp = new MultiDSAdminClientStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(),null, null,
                      AdminClientStoreProviders.getAdminClientProvider());
            macp.addListener(AdminClientStoreProviders.getACMP(cn));
            macp.addListener(AdminClientStoreProviders.getACFSP(cn));
            macp.addListener(AdminClientStoreProviders.getMariaACS(cn, getMariaDBConnectionPoolProvider()));
            macp.addListener(AdminClientStoreProviders.getMysqlACS(cn, getMySQLConnectionPoolProvider()));
            macp.addListener(AdminClientStoreProviders.getPostgresACS(cn, getPgConnectionPoolProvider()));
            AdminClientStore acs = (AdminClientStore) macp.get();
            System.err.println("Got admin client store" + acs.getClass().getSimpleName());
        }
        return macp;
    }
    protected MultiDSPermissionStoreProvider getMpp() {
        if (mpp == null) {
            mpp = new MultiDSPermissionStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(),
                    null, null, PermissionStoreProviders.getPermissionProvider());
            mpp.addListener(PermissionStoreProviders.getM(cn));
            mpp.addListener(PermissionStoreProviders.getFSP(cn));
            mpp.addListener(PermissionStoreProviders.getMariaPS(cn, getMariaDBConnectionPoolProvider()));
            mpp.addListener(PermissionStoreProviders.getPostgresPS(cn, getPgConnectionPoolProvider()));
            mpp.addListener(PermissionStoreProviders.getMysqlPS(cn, getMySQLConnectionPoolProvider()));
        }
        return mpp;
    }

    protected MultiDSClientApprovalStoreProvider getCASP() {
        if (casp == null) {
            casp = new MultiDSClientApprovalStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            final ClientApprovalProvider caProvider = new ClientApprovalProvider();
            ClientApproverConverter cp = new ClientApproverConverter(caProvider);
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

        return (T) new ServiceEnvironmentImpl(loggerProvider.get(),
                getMyProxyFacadeProvider(),
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
                getMpp(),
                getMacp());
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
        se2.setDebugOn(Boolean.parseBoolean(Configurations.getFirstAttribute(cn, OA4MPConfigTags.DEBUG)));

        // part 2. This is done after main config load.
        Object[] polling = loadPolling();


        if (polling != null) {
            info("Loading polling for " + polling[0]);
            AbstractCLIApprover.ClientApprovalThread cat = new AbstractCLIApprover.ClientApprovalThread(myLogger, se2, (File) polling[0], (Long) polling[1]);
            se2.setClientApprovalThread(cat);
        }

        if (se2.isDebugOn()) {
            info("Debug mode enabled.");
            for (MyProxyServiceFacade x : se2.getMyProxyServices()) {
                debug("loaded myproxy configuration for " + x.getFacadeConfiguration().getHostname() + ":" + x.getFacadeConfiguration().getPort());
            }
        }

        return (T) se2;
    }
}
