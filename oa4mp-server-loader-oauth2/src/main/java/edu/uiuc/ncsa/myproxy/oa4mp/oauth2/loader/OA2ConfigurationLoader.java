package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.LDAPClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CM7591Config;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CMConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CMConfigs;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ClientManagementConstants;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json.JSONStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json.MultiJSONStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628ServletConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.MultiDSAdminClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSTransactionProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSSQLClientApprovalStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApprovalMemoryStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientApproverConverter;
import edu.uiuc.ncsa.qdl.config.QDLConfigurationConstants;
import edu.uiuc.ncsa.qdl.config.QDLConfigurationLoader;
import edu.uiuc.ncsa.qdl.config.QDLEnvironment;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.AGI2;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATI2;
import edu.uiuc.ncsa.security.oauth_2_0.server.PAI2;
import edu.uiuc.ncsa.security.oauth_2_0.server.RFC8628Constants;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.TRANSACTION_ID;
import static edu.uiuc.ncsa.security.core.configuration.Configurations.*;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigTags.ACCESS_TOKEN_LIFETIME;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigTags.*;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/23/13 at  1:50 PM
 */
public class OA2ConfigurationLoader<T extends ServiceEnvironmentImpl> extends AbstractConfigurationLoader<T> {
    public static final String STRICT_ACLS = "strict_acls"; // for QDL
    public static final String SAFE_GARBAGE_COLLECTION = "safe_gc";
    public static final String PRINT_TS_IN_DEBUG = "printTSInDebug";
    public static final String NOTIFY_ADMIN_CLIENT_ADDRESSES = "notifyACEmailAddresses";
    public static final String CLEANUP_INTERVAL_TAG = "cleanupInterval";
    public static final String RFC7636_REQUIRED_TAG = "rfc7636Required";

    /**
     * Default is 15 days. Internally the refresh lifetime (as all date-ish things) are in milliseconds
     * though the configuration file is assumed to be in seconds.
     */
    public static long REFRESH_TOKEN_LIFETIME_DEFAULT = 15 * 24 * 3600 * 1000L; // 15 days
    public static long MAX_REFRESH_TOKEN_LIFETIME_DEFAULT = 2 * REFRESH_TOKEN_LIFETIME_DEFAULT; // 30 days

    public static long ACCESS_TOKEN_LIFETIME_DEFAULT = 15 * 60 * 1000L; // 15 minutes
    public static long MAX_ACCESS_TOKEN_LIFETIME_DEFAULT = 2 * ACCESS_TOKEN_LIFETIME_DEFAULT; // 30 minutes

    public static long ID_TOKEN_LIFETIME_DEFAULT = 15 * 60 * 1000L; // 15 minutes
    public static long MAX_ID_TOKEN_LIFETIME_DEFAULT = MAX_ACCESS_TOKEN_LIFETIME_DEFAULT; // 30 minutes

    public static long AUTHORIZATION_GRANT_LIFETIME_DEFAULT = 15 * 60 * 1000L; // 15 minutes
    public static long MAX_AUTHORIZATION_GRANT_LIFETIME_DEFAULT = 2 * AUTHORIZATION_GRANT_LIFETIME_DEFAULT; // 30 minutes

    //This is divisible by 3 and greater than 256,
    // so when it is base64 encoded there will be no extra characters:
    public static int CLIENT_SECRET_LENGTH_DEFAULT = 258;

    public static long CLEANUP_INTERVAL_DEFAULT = 30 * 60 * 1000L; // 30 minutes

    public OA2ConfigurationLoader(ConfigurationNode node) {
        super(node);
    }

    public OA2ConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public T createInstance() {
        try {
            initialize();
            T se = (T) new OA2SE(loggerProvider.get(),
                    getTransactionStoreProvider(),
                    getTXStoreProvider(),
                    getVOStoreProvider(),
                    getClientStoreProvider(),
                    getMaxAllowedNewClientRequests(),
                    getAGLifetime(),
                    getMaxAGLifetime(),
                    getIDTokenLifetime(),
                    getMaxIDTokenLifetime(),
                    getMaxATLifetime(),
                    getATLifetime(),
                    getMaxRTLifetime(),
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
                    getJSONWebKeys(),
                    getIssuer(),
                    isUtilServerEnabled(),
                    isOIDCEnabled(),
                    getMultiJSONStoreProvider(),
                    getCmConfigs(),
                    getQDLEnvironment(),
                    isRFC8693Enabled(),
                    isQdlStrictACLS(),
                    isSafeGC(),
                    getRFC8628ServletConfig(),
                    isRFC8628Enabled(),
                    isprintTSInDebug(),
                    getCleanupInterval(),
                    isNotifyACEventEmailAddresses(),
                    isRFC7636Required());

            if (getClaimSource() instanceof BasicClaimsSourceImpl) {
                ((BasicClaimsSourceImpl) getClaimSource()).setOa2SE((OA2SE) se);
            }
            return se;
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new GeneralException("Error: Could not create the runtime environment", e);
        }
    }

    RFC8628ServletConfig rfc8628ServletConfig = null;

    public RFC8628ServletConfig getRFC8628ServletConfig() {
        if (rfc8628ServletConfig == null) {
            rfc8628ServletConfig = new RFC8628ServletConfig();
            List kids = cn.getChildren(OA4MPConfigTags.DEVICE_FLOW_SERVLET);
            //set default
            String address = getServiceAddress().toString();
            if (!address.endsWith("/")) {
                address = address + "/";
            }
            rfc8628ServletConfig.deviceEndpoint = address + RFC8628Constants.VERIFICATION_URI_ENDPOINT;
            rfc8628ServletConfig.deviceAuthorizationEndpoint = address + RFC8628Constants.DEVICE_AUTHORIZATION_ENDPOINT;
            if (!kids.isEmpty()) {
                // empty means either they have an empty entry or that they have no entry.
                rfc8628Enabled = Boolean.TRUE; // if they supply this, then
                ConfigurationNode sn = (ConfigurationNode) kids.get(0);
                String x = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_SERVLET_URI);
                if (!StringUtils.isTrivial(x)) {
                    rfc8628ServletConfig.deviceEndpoint = x;
                }

                x = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_AUTHORIZATION_URI);
                if (!StringUtils.isTrivial(x)) {
                    rfc8628ServletConfig.deviceAuthorizationEndpoint = x;
                }
                x = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_LIFETIME);
                try {
                    rfc8628ServletConfig.lifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                } catch (NumberFormatException numberFormatException) {

                }
                x = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_INTERVAL);
                if (!StringUtils.isTrivial(x)) {
                    try {
                        rfc8628ServletConfig.interval = ConfigUtil.getValueSecsOrMillis(x, true);
                    } catch (NumberFormatException nfe) {
                        // do nothing. Default is set in servlet config.
                    }
                }
                x = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_USER_CODE_LENGTH);
                if (!StringUtils.isTrivial(x)) {
                    try {
                        rfc8628ServletConfig.userCodeLength = Integer.parseInt(x);
                    } catch (NumberFormatException nfx) {
                    }
                }
                String separator = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_CODE_SEPARATOR);
                if (!StringUtils.isTrivial(separator)) {
                    rfc8628ServletConfig.userCodeSeperator = separator;
                }

                String codeChars = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_CODE_CHARS);
                if (!StringUtils.isTrivial(codeChars)) {
                    rfc8628ServletConfig.codeChars = codeChars.toCharArray();
                }

                x = getFirstAttribute(sn, OA4MPConfigTags.DEVICE_FLOW_CODE_PERIOD_LENGTH);
                if (!StringUtils.isTrivial(x)) {
                    try {
                        rfc8628ServletConfig.userCodePeriodLength = Integer.parseInt(x);
                    } catch (NumberFormatException nfx) {
                    }
                }

            }
        }
        return rfc8628ServletConfig;
    }

    protected QDLEnvironment getQDLEnvironment() {
        ConfigurationNode node = getFirstNode(cn, QDLConfigurationConstants.CONFIG_TAG_NAME);
        if (node == null) {
            return new QDLEnvironment();// no op. This is disabled.
        }
        // Note that the first argument is the name fo the file. In server mode this won't be available anyway
        // and is optional.
        String x = getFirstAttribute(node, STRICT_ACLS);
        if (!isTrivial(x)) {
            try {
                qdlStrictACLS = Boolean.parseBoolean(x);
            } catch (Throwable t) {
                // nothing to do.
            }
        }
        QDLConfigurationLoader loader = new QDLConfigurationLoader("(none)", node, loggerProvider.get());
        return loader.load();
    }

    String notifyACEventEmailAddresses = null;

    public String isNotifyACEventEmailAddresses() {
        if (notifyACEventEmailAddresses == null) {
            notifyACEventEmailAddresses = getFirstAttribute(cn, NOTIFY_ADMIN_CLIENT_ADDRESSES);
            DebugUtil.trace(this, "admin client notification addresses: " + notifyACEventEmailAddresses);
        }
        return notifyACEventEmailAddresses;
    }

    protected Boolean rfc7636Required = null;

    public Boolean isRFC7636Required() {
        if (rfc7636Required == null) {
            String raw = getFirstAttribute(cn, RFC7636_REQUIRED_TAG);
            try {
                rfc7636Required = Boolean.parseBoolean(raw);
            } catch (Throwable t) {
                rfc7636Required = Boolean.FALSE;// default
            }
        }
        return rfc7636Required;
    }

    protected Boolean printTSInDebug = false;

    public boolean isprintTSInDebug() {
        if (printTSInDebug == null) {
            try {
                printTSInDebug = Boolean.parseBoolean(getFirstAttribute(cn, PRINT_TS_IN_DEBUG));
            } catch (Throwable t) {
                // use default which is to doo safe garbage collection.
                // We let this be null to trigger pulling the value, if any, out of the
                // the configuration
                printTSInDebug = Boolean.TRUE;
            }
            DebugUtil.trace(this, "print TS in debug? " + printTSInDebug);
        }
        return printTSInDebug;
    }

    long cleanupInterval = -1;

    public long getCleanupInterval() {
        if (cleanupInterval < 0) {
            try {

                String raw = getFirstAttribute(cn, CLEANUP_INTERVAL_TAG);
                if (StringUtils.isTrivial(raw)) {
                    cleanupInterval = CLEANUP_INTERVAL_DEFAULT;
                } else {
                    cleanupInterval = ConfigUtil.getValueSecsOrMillis(raw, true);
                }
            } catch (Throwable t) {
                // use default which is to doo safe garbage collection.
                // We let this be null to trigger pulling the value, if any, out of the
                // the configuration
                cleanupInterval = CLEANUP_INTERVAL_DEFAULT;
            }
            DebugUtil.trace(this, CLEANUP_INTERVAL_TAG + " set to " + cleanupInterval);
        }
        return cleanupInterval;
    }

    public boolean isSafeGC() {
        if (safeGC == null) {
            try {
                safeGC = Boolean.parseBoolean(getFirstAttribute(cn, SAFE_GARBAGE_COLLECTION));
            } catch (Throwable t) {
                // use default which is to doo safe garbage collection.
                // We let this be null to trigger pulling the value, if any, out of the
                // the configuration
                safeGC = Boolean.TRUE;
            }
            DebugUtil.trace(this, "safe garbage collection enabled? " + safeGC);
        }
        return safeGC;
    }

    Boolean safeGC = true;

    public boolean isQdlStrictACLS() {
        return qdlStrictACLS;
    }

    boolean qdlStrictACLS = false;

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

    Boolean utilServerEnabled = null;

    protected Boolean isUtilServerEnabled() {
        if (utilServerEnabled == null) {
            try {
                utilServerEnabled = Boolean.parseBoolean(getFirstAttribute(cn, OA4MPConfigTags.ENABLE_UTIL_SERVLET));
            } catch (Throwable t) {
                // use default which is to enable. We let this be null to trigger pulling the value, if any, out of the
                // the configuration
                utilServerEnabled = Boolean.TRUE;
            }
        }
        return utilServerEnabled;
    }

    Boolean rfc8693Enabled = null;

    protected Boolean isRFC8693Enabled() {
        if (rfc8693Enabled == null) {
            try {
                rfc8693Enabled = Boolean.parseBoolean(getFirstAttribute(cn, OA4MPConfigTags.ENABLE_RFC8693_SUPPORT));
            } catch (Throwable t) {
                // use default which is to enable. We let this be null to trigger pulling the value, if any, out of the
                // the configuration
                rfc8693Enabled = Boolean.TRUE;
            }
            DebugUtil.trace(this, "RFC 8693 support enabled? " + rfc8693Enabled);
        }
        return rfc8693Enabled;
    }

    Boolean rfc8628Enabled = null;

    protected Boolean isRFC8628Enabled() {
        if (rfc8628Enabled == null) {
            try {
                rfc8628Enabled = Boolean.parseBoolean(getFirstAttribute(cn, OA4MPConfigTags.ENABLE_RFC8628_SUPPORT));
            } catch (Throwable t) {
                // use default which is to disabled. We let this be null to trigger pulling the value, if any, out of the
                // the configuration
                rfc8628Enabled = Boolean.FALSE;
            }
            DebugUtil.trace(this, "RFC 8628 support enabled? " + rfc8628Enabled);
        }
        return rfc8628Enabled;
    }

    protected CMConfigs createDefaultCMConfig() {
        CMConfigs cmConfigs = new CMConfigs();
        String serverAddress = getServiceAddress().toString();
        if (!serverAddress.endsWith("/")) {
            serverAddress = serverAddress + "/";
        }
        CMConfig tempCfg = new CMConfig(ClientManagementConstants.OA4MP_VALUE,
                URI.create(serverAddress + ClientManagementConstants.DEFAULT_OA4MP_ENDPOINT),
                true);
        cmConfigs.put(tempCfg);
        tempCfg = new CM7591Config(ClientManagementConstants.RFC_7591_VALUE,
                URI.create(serverAddress + ClientManagementConstants.DEFAULT_RFC7591_ENDPOINT),
                true, null, false, false);
        cmConfigs.put(tempCfg);
        // NOTE there is no difference in endpoints for RFC 7591 and 7592! The question is if
        // the client management protocol endpoint also supports RFC 7592.
        tempCfg = new CMConfig(ClientManagementConstants.RFC_7592_VALUE,
                URI.create(serverAddress + ClientManagementConstants.DEFAULT_RFC7591_ENDPOINT),
                true);

        cmConfigs.put(tempCfg);
        return cmConfigs;
    }

    /*
    A typical entry we are parsing looks like this

     <clientManagement>
        <api protocol="rfc7951" enable="true" endpoint="oidc-cm" anonymousOK="true"/>
        <api protocol="rfc7952" enable="true" endpoint="oidc-cm"/>
        <api protocol="oa4mp" enable="true"  url="https://foo.bar/oauth2/clients"/>
     </clientManagement>

     Note that EITHER the endpoint is given (and the full url is then constructed here)
     OR the complete url is given. Giving the url has right of way. The configuration object
     only has URLs and they are resolved here from the server address.

     In this example, the endpoints for the RFCs are constructed but the native OA4MP endpoint
     is explicitly given. These are needed since responses must include an actual address for
     clients to come to for future updates, etc. 
     */
    public CMConfigs getCmConfigs() {
        if (cmConfigs == null) {
            List<ConfigurationNode> kids = cn.getChildren(ClientManagementConstants.CLIENT_MANAGEMENT_TAG);
            CMConfigs defaultCMConfigs = createDefaultCMConfig();
            if (kids == null || kids.isEmpty()) {
                cmConfigs = defaultCMConfigs;
                return cmConfigs; // missing the entire element (which is fine)  so jump out...
            }
            if (1 < kids.size()) {
                throw new IllegalArgumentException("Multiple " + ClientManagementConstants.CLIENT_MANAGEMENT_TAG + " elements found.");
            }
            ConfigurationNode cmNode = kids.get(0); // only process first one found
            kids = cmNode.getChildren(); // This should have the API elements in it
            cmConfigs = new CMConfigs();
            String e = getFirstAttribute(cmNode, ClientManagementConstants.ENABLE_SERVICE);
            if (!isTrivial(e)) {
                try {
                    cmConfigs.setEnabled(Boolean.parseBoolean(e));
                } catch (Throwable t) {
                    cmConfigs.setEnabled(true); // default
                }
            }
            if (!cmConfigs.isEnabled()) {
                return cmConfigs;
            }
            String serverAddress = getServiceAddress().toString();
            // need to loop through all kids.
            for (ConfigurationNode sn : kids) {
                if (sn.getName().equals(ClientManagementConstants.API_TAG)) {
                    try {
                        CMConfig cfg = CMConfigs.createConfigEntry(
                                getFirstAttribute(sn, ClientManagementConstants.PROTOCOL_ATTRIBUTE),
                                serverAddress,
                                getFirstAttribute(sn, ClientManagementConstants.ENDPOINT_ATTRIBUTE),
                                getFirstAttribute(sn, ClientManagementConstants.FULL_URL_ATTRIBUTE),
                                getFirstAttribute(sn, ClientManagementConstants.ENABLE_SERVICE),
                                getFirstAttribute(sn, ClientManagementConstants.RFC_7591_TEMPLATE),
                                getFirstAttribute(sn, ClientManagementConstants.RFC_7591_ANONYMOUS_OK),
                                getFirstAttribute(sn, ClientManagementConstants.RFC_7591_AUTO_APPROVE),
                                getFirstAttribute(sn, ClientManagementConstants.RFC_7591_AUTO_APPROVER_NAME)
                        );
                        cmConfigs.put(cfg);
                    } catch (Throwable t) {
                        ServletDebugUtil.warn(this, "error loading client management api entry \"" + t.getMessage() + "\"");
                    }
                }
            }
            // Make sure that no matter what, the configuration for this is usable. Not
            // having an entry means use the default.
            if (cmConfigs.isEmpty()) {
                ServletDebugUtil.warn(this, "Warning: none of the entries in the client managment element parsed. Using defaults...");
            }
            if (!cmConfigs.hasOA4MPConfig()) {
                cmConfigs.put(defaultCMConfigs.getOA4MPConfig());
            }
            if (!cmConfigs.hasRFC7592Config()) {
                cmConfigs.put(defaultCMConfigs.getRFC7592Config());
            }
            if (!cmConfigs.hasRFC7591Config()) {
                cmConfigs.put(defaultCMConfigs.getRFC7591Config());
            }
        }
        return cmConfigs;
    }

    CMConfigs cmConfigs;

    public MultiJSONStoreProvider getMultiJSONStoreProvider() {
        if (multiJSONStoreProvider == null) {

            multiJSONStoreProvider = new MultiJSONStoreProvider(cn,
                    isDefaultStoreDisabled(),
                    loggerProvider.get(),
                    null,
                    null);
            multiJSONStoreProvider.addListener(JSONStoreProviders.getJSMSP(cn));
            multiJSONStoreProvider.addListener(JSONStoreProviders.getJSFSP(cn));
            multiJSONStoreProvider.addListener(JSONStoreProviders.getMariaJS(cn, getMariaDBConnectionPoolProvider()));
            multiJSONStoreProvider.addListener(JSONStoreProviders.getMySQLJS(cn, getMySQLConnectionPoolProvider()));
            multiJSONStoreProvider.addListener(JSONStoreProviders.getPostgresJS(cn, getPgConnectionPoolProvider()));

        }
        return multiJSONStoreProvider;
    }

    protected MultiJSONStoreProvider multiJSONStoreProvider;


    protected MultiDSAdminClientStoreProvider macp;

    protected MultiDSAdminClientStoreProvider getMacp() {
        if (macp == null) {
            macp = new MultiDSAdminClientStoreProvider(cn,
                    isDefaultStoreDisabled(),
                    loggerProvider.get(),
                    null,
                    null,
                    AdminClientStoreProviders.getAdminClientProvider());
            macp.addListener(AdminClientStoreProviders.getACMP(cn));
            macp.addListener(AdminClientStoreProviders.getACFSP(cn));
            macp.addListener(AdminClientStoreProviders.getMariaACS(cn, getMariaDBConnectionPoolProvider()));
            macp.addListener(AdminClientStoreProviders.getMysqlACS(cn, getMySQLConnectionPoolProvider()));
            macp.addListener(AdminClientStoreProviders.getPostgresACS(cn, getPgConnectionPoolProvider()));
            macp.addListener(AdminClientStoreProviders.getDerbyACS(cn, getDerbyConnectionPoolProvider()));
            AdminClientStore acs = (AdminClientStore) macp.get();
        }
        return macp;
    }

    protected JSONWebKeys getJSONWebKeys() {
        ConfigurationNode node = getFirstNode(cn, "JSONWebKey");
        if (node == null) {
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

        if (keys == null) {
            throw new IllegalStateException("Error: Could not load signing keys");
        }
        if (keys.size() == 1) {
            // CIL-1067
            // If there is a single key in the file, use that as the default.
            keys.setDefaultKeyID(keys.keySet().iterator().next());
        } else {
            keys.setDefaultKeyID(getFirstAttribute(node, "defaultKeyID"));
        }
        return keys;
    }

    @Override
    public Provider<AGIssuer> getAGIProvider() {
        if (agip == null) {
            return new Provider<AGIssuer>() {
                @Override
                public AGIssuer get() {
                    return new AGI2(getTokenForgeProvider().get(), getServiceAddress(), isOIDCEnabled());
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
            final ClientApproverConverter cp = new ClientApproverConverter(caKeys, caProvider);
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

    public class OA4MP2TProvider extends DSTransactionProvider<OA2ServiceTransaction> {
        public OA4MP2TProvider(IdentifierProvider<Identifier> idProvider) {
            super(idProvider);
        }

        @Override
        public OA2ServiceTransaction get(boolean createNewIdentifier) {
            return new OA2ServiceTransaction(createNewId(createNewIdentifier));
        }
    }


    // Authorization grants lifetime
    long agLifetime = -1L;


    protected long getAGLifetime() {
        if (agLifetime < 0) {
            String x = getFirstAttribute(cn, AUTH_GRANT_LIFETIME);
            if (isTrivial(x)) {
                agLifetime = AUTHORIZATION_GRANT_LIFETIME_DEFAULT;
            } else {
                try {
                    agLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                    //agLifetime = Long.parseLong(x) * 1000; // The configuration file has this in seconds. Internally this is ms.
                } catch (Throwable t) {
                    agLifetime = AUTHORIZATION_GRANT_LIFETIME_DEFAULT;
                }
            }
        }
        return agLifetime;
    }

    long idTokenLifetime = -1L;

    protected long getIDTokenLifetime() {
        if (idTokenLifetime < 0) {
            String x = getFirstAttribute(cn, DEFAULT_ID_TOKEN_LIFETIME);
            if (isTrivial(x)) {
                idTokenLifetime = ID_TOKEN_LIFETIME_DEFAULT;
            } else {
                try {
                    idTokenLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                } catch (Throwable t) {
                    idTokenLifetime = ID_TOKEN_LIFETIME_DEFAULT;
                }
            }
        }
        return idTokenLifetime;
    }

    public long getMaxIDTokenLifetime() {
        if (maxIDTokenLifetime < 0) {
            String x = getFirstAttribute(cn, DEFAULT_ID_TOKEN_LIFETIME);
            if (isTrivial(x)) {
                maxIDTokenLifetime = MAX_ID_TOKEN_LIFETIME_DEFAULT;
            } else {
                try {
                    maxIDTokenLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                } catch (Throwable t) {
                    maxIDTokenLifetime = MAX_ID_TOKEN_LIFETIME_DEFAULT;
                }
            }
        }
        return maxIDTokenLifetime;
    }

    long maxIDTokenLifetime = -1L;


    // access token lifetime


    long atLifetime = -1L;

    protected long getATLifetime() {
        if (atLifetime < 0) {
            String x = getFirstAttribute(cn, DEFAULT_ACCESS_TOKEN_LIFETIME);
            if (isTrivial(x)) {
                // Old way
                x = getFirstAttribute(cn, ACCESS_TOKEN_LIFETIME);
            }
            if (isTrivial(x)) {
                atLifetime = ACCESS_TOKEN_LIFETIME_DEFAULT;
            } else {
                try {
                    atLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                } catch (Throwable t) {
                    atLifetime = ACCESS_TOKEN_LIFETIME_DEFAULT;
                }
            }
        }
        return atLifetime;
    }

    long maxAGLifetime = -1L;

    public long getMaxAGLifetime() {
        if (maxAGLifetime < 0) {
            String x = getFirstAttribute(cn, MAX_AUTH_GRANT_LIFETIME);
            if (isTrivial(x)) {
                maxAGLifetime = MAX_AUTHORIZATION_GRANT_LIFETIME_DEFAULT;
            } else {
                try {
                    maxAGLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                } catch (Throwable t) {
                    maxAGLifetime = MAX_AUTHORIZATION_GRANT_LIFETIME_DEFAULT;
                }
            }
        }
        return maxAGLifetime;
    }

    public long getMaxATLifetime() {
        if (maxATLifetime < 0) {
            String x = getFirstAttribute(cn, MAX_ACCESS_TOKEN_LIFETIME);
            if (isTrivial(x)) {
                maxATLifetime = MAX_ACCESS_TOKEN_LIFETIME_DEFAULT;
            } else {
                try {
                    maxATLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                } catch (Throwable t) {
                    maxATLifetime = MAX_ACCESS_TOKEN_LIFETIME_DEFAULT;
                }
            }
        }
        return maxATLifetime;
    }

    public void setMaxATLifetime(long maxATLifetime) {
        this.maxATLifetime = maxATLifetime;
    }

    long maxATLifetime = -1L;

    long maxRTLifetime = -1L;

    public long getMaxRTLifetime() {
        if (maxRTLifetime < 0) {
            String x = getFirstAttribute(cn, MAX_REFRESH_TOKEN_LIFETIME);
            if (isTrivial(x)) {
                maxRTLifetime = MAX_REFRESH_TOKEN_LIFETIME_DEFAULT;
            } else {
                try {
                    maxRTLifetime = ConfigUtil.getValueSecsOrMillis(x, true);
                    //maxRTLifetime = Long.parseLong(x) * 1000; // The configuration file has this in seconds. Internally this is ms.
                } catch (Throwable t) {
                    maxRTLifetime = MAX_REFRESH_TOKEN_LIFETIME_DEFAULT;
                }
            }
        }
        return maxRTLifetime;
    }

    String issuer = null;

    protected String getIssuer() {
        if (issuer == null) {
            String x = getFirstAttribute(cn, ISSUER);
            // Fixes OAUTH-214
            if (x == null || x.length() == 0) {
                return null;
            } else {
                issuer = x;
            }
        }
        return issuer;

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
                    maxClientRefreshTokenLifetime = ConfigUtil.getValueSecsOrMillis(x, true); // The configuration file has this in seconds. Internally this is ms.
                    //maxClientRefreshTokenLifetime = Long.parseLong(x) * 1000; // The configuration file has this in seconds. Internally this is ms.
                } catch (Throwable t) {
                    maxClientRefreshTokenLifetime = 13 * 30 * 24 * 3600 * 1000L; // default of 13 months.
                }
            }
        }
        return maxClientRefreshTokenLifetime;
    }

    Boolean oidcEnabled = null;

    public boolean isOIDCEnabled() {
        if (oidcEnabled == null) {
            String x = getFirstAttribute(cn, OIDC_SUPPORT_ENABLED);
            if (x == null) {
                oidcEnabled = Boolean.TRUE; // default.
            } else {
                try {
                    oidcEnabled = Boolean.valueOf(x);
                } catch (Throwable t) {
                    info("Could not parse OIDC enabled flag, setting default to true");
                    oidcEnabled = Boolean.TRUE;
                }
            }
        }
        return oidcEnabled;
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
    protected ClaimSource claimSource;

    public ClaimSource getClaimSource() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        DebugUtil.trace(this, "Getting scope handler " + claimSource);
        if (claimSource == null) {
            // This gets the scopes if any and injects them into the scope handler.
            if (0 < cn.getChildrenCount(SCOPES)) {
                String scopeHandlerName = getFirstAttribute(Configurations.getFirstNode(cn, SCOPES), SCOPE_HANDLER);
                if (scopeHandlerName != null) {
                    Class<?> k = Class.forName(scopeHandlerName);
                    Object x = k.newInstance();
                    if (!(x instanceof ClaimSource)) {
                        throw new GeneralException("The scope handler specified by the class name \"" +
                                scopeHandlerName + "\" does not extend the ScopeHandler " +
                                "interface and therefore cannot be used to handle scopes.");
                    }
                    claimSource = (ClaimSource) x;
                } else {
                    info("Scope handler attribute found in configuration, but no value was found for it. Skipping custom loaded scope handling.");
                }
            }

            // no scopes element, so just use the basic handler.
            if (claimSource == null) {

                DebugUtil.trace(this, "No server-wide configured Scope handler");
                if (getLdapConfiguration().isEnabled()) {
                    DebugUtil.trace(this, "   LDAP scope handler enabled, creating default");
                    claimSource = new LDAPClaimsSource(getLdapConfiguration(), myLogger);
                } else {
                    DebugUtil.trace(this, "   LDAP scope handler disabled, creating basic");
                    ClaimSourceConfiguration claimSourceConfiguration = new ClaimSourceConfiguration();
                    claimSourceConfiguration.setEnabled(false);
                    claimSource = new BasicClaimsSourceImpl();
                    claimSource.setConfiguration(claimSourceConfiguration);
                }
            }
            claimSource.setScopes(getScopes());
            DebugUtil.trace(this, "   Actual scope handler = " + claimSource.getClass().getSimpleName());

        }
        return claimSource;
    }

    LDAPConfiguration ldapConfiguration;

    protected LDAPConfiguration getLdapConfiguration() {
        if (ldapConfiguration == null) {
            LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
            ldapConfiguration = ldapConfigurationUtil.getLdapConfiguration(myLogger, cn);
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
            csp.addListener(new OA2ClientSQLStoreProvider(getDerbyConnectionPoolProvider(),
                    OA4MPConfigTags.DERBY_STORE,
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

    protected SQLTXRStoreProvider createSQLTXRecordP(ConfigurationNode config,
                                                     ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                                     String type,
                                                     TXRecordProvider<? extends TXRecord> tp,
                                                     Provider<TokenForge> tfp,
                                                     TXRecordConverter converter) {
        return new SQLTXRStoreProvider(config, cpp, type, converter, tp);
    }


    protected SQLVOStoreProvider createSQLVOP(ConfigurationNode config,
                                              ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                              String type,
                                              VOProvider<? extends VirtualOrganization> tp,
                                              Provider<TokenForge> tfp,
                                              VOConverter converter) {
        return new SQLVOStoreProvider(config, cpp, type, converter, tp);
    }

    Provider<VOStore> voStoreProvider;

    protected Provider<VOStore> getVOStoreProvider() {
        VOProvider voProvider = new VOProvider(null, (OA2TokenForge) getTokenForgeProvider().get());
        VOConverter voConverter = new VOConverter(new VOSerializationKeys(), voProvider);
        return getVOStoreProvider(voProvider, voConverter);
    }

    protected Provider<VOStore> getVOStoreProvider(VOProvider voProvider,
                                                   VOConverter<? extends VirtualOrganization> voConverter) {
        if (voStoreProvider == null) {
            VOMultiStoreProvider storeProvider = new VOMultiStoreProvider(cn,
                    isDefaultStoreDisabled(),
                    loggerProvider.get(),
                    null, null,
                    voProvider, voConverter);

            storeProvider.addListener(createSQLVOP(cn,
                    getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    voProvider,
                    getTokenForgeProvider(),
                    voConverter));
            storeProvider.addListener(createSQLVOP(cn,
                    getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    voProvider,
                    getTokenForgeProvider(),
                    voConverter));
            storeProvider.addListener(createSQLVOP(cn,
                    getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    voProvider,
                    getTokenForgeProvider(),
                    voConverter));
            storeProvider.addListener(createSQLVOP(cn,
                    getDerbyConnectionPoolProvider(),
                    OA4MPConfigTags.DERBY_STORE,
                    voProvider,
                    getTokenForgeProvider(),
                    voConverter));

            storeProvider.addListener(new VOFSProvider(cn, voProvider, voConverter));
            storeProvider.addListener(new TypedProvider<VOStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.VIRTUAL_ORGANIZATION_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public VOStore get() {
                    return new VOMemoryStore(voProvider, voConverter);
                }

            });
            voStoreProvider = storeProvider;
        }
        return voStoreProvider;
    }


    Provider<TXStore> txStoreProvider;

    protected Provider<TXStore> getTXStoreProvider() {
        TXRecordProvider txRecordProvider = new TXRecordProvider(null, (OA2TokenForge) getTokenForgeProvider().get());
        TXRecordConverter txRecordConverter = new TXRecordConverter(new TXRecordSerializationKeys(), txRecordProvider);
        return getTXStoreProvider(txRecordProvider, txRecordConverter);
    }

    protected Provider<TXStore> getTXStoreProvider(TXRecordProvider txRecordProvider,
                                                   TXRecordConverter<? extends TXRecord> txRecordConverter) {
        if (txStoreProvider == null) {
            TXMultiStoreProvider storeProvider = new TXMultiStoreProvider(cn,
                    isDefaultStoreDisabled(),
                    loggerProvider.get(),
                    null, null,
                    txRecordProvider, txRecordConverter);

            storeProvider.addListener(createSQLTXRecordP(cn,
                    getMySQLConnectionPoolProvider(),
                    OA4MPConfigTags.MYSQL_STORE,
                    txRecordProvider,
                    getTokenForgeProvider(),
                    txRecordConverter));
            storeProvider.addListener(createSQLTXRecordP(cn,
                    getMariaDBConnectionPoolProvider(),
                    OA4MPConfigTags.MARIADB_STORE,
                    txRecordProvider,
                    getTokenForgeProvider(),
                    txRecordConverter));
            storeProvider.addListener(createSQLTXRecordP(cn,
                    getPgConnectionPoolProvider(),
                    OA4MPConfigTags.POSTGRESQL_STORE,
                    txRecordProvider,
                    getTokenForgeProvider(),
                    txRecordConverter));
            storeProvider.addListener(createSQLTXRecordP(cn,
                    getDerbyConnectionPoolProvider(),
                    OA4MPConfigTags.DERBY_STORE,
                    txRecordProvider,
                    getTokenForgeProvider(),
                    txRecordConverter));

            storeProvider.addListener(new TXFSProvider(cn, txRecordProvider, txRecordConverter));
            storeProvider.addListener(new TypedProvider<TXStore>(cn, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.TOKEN_EXCHANGE_RECORD_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public TXStore get() {
                    return new TXMemoryStore(txRecordProvider, txRecordConverter);
                }

            });
            txStoreProvider = storeProvider;
        }
        return txStoreProvider;
    }


    protected Provider<TransactionStore> getTSP(IdentifiableProvider tp,
                                                OA2TConverter<? extends OA2ServiceTransaction> tc) {
        if (tsp == null) {
            final IdentifiableProvider tp1 = tp; // since this is referenced in an inner class below.
            OA2MultiTypeTransactionProvider storeProvider = new OA2MultiTypeTransactionProvider(cn, isDefaultStoreDisabled(), loggerProvider.get(), tp);
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
            storeProvider.addListener(createSQLTSP(cn,
                    getDerbyConnectionPoolProvider(),
                    OA4MPConfigTags.DERBY_STORE,
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
        IdentifiableProvider tp = new ST2Provider(new OA4MPIdentifierProvider(TRANSACTION_ID, false));
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
                return new ATI2(getTokenForgeProvider().get(), getServiceAddress(), isOIDCEnabled());
            }
        };
    }

    @Override
    public Provider<PAIssuer> getPAIProvider() {
        return new Provider<PAIssuer>() {
            @Override
            public PAIssuer get() {
                return new PAI2(getTokenForgeProvider().get(), getServiceAddress(), isOIDCEnabled());
            }
        };
    }


    @Override
    public IdentifiableProvider<? extends Client> getClientProvider() {
        return new OA2ClientProvider(new OA4MPIdentifierProvider(OA2Constants.CLIENT_ID, false));
    }

    @Override
    public String getVersionString() {
        return "OAuth 2 for MyProxy, version " + VERSION_NUMBER;
    }

}
