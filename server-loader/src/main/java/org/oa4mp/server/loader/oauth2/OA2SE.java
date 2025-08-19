package org.oa4mp.server.loader.oauth2;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.delegation.server.issuers.AGIssuer;
import org.oa4mp.delegation.server.issuers.ATIssuer;
import org.oa4mp.delegation.server.issuers.PAIssuer;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.server.api.storage.servlet.AuthorizationServletConfig;
import org.oa4mp.server.loader.oauth2.claims.BasicClaimsSourceImpl;
import org.oa4mp.server.loader.oauth2.cm.CMConfigs;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.loader.oauth2.servlet.DBServiceConfig;
import org.oa4mp.server.loader.oauth2.servlet.RFC8628ServletConfig;
import org.oa4mp.server.loader.oauth2.storage.tx.TXStore;
import org.oa4mp.server.loader.oauth2.storage.vi.VIStore;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.loader.qdl.scripting.OA2QDLEnvironment;

import javax.inject.Provider;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/14 at  4:16 PM
 */
public class OA2SE extends ServiceEnvironmentImpl {
    public OA2SE(MyLoggingFacade logger,
                 Provider<TransactionStore> tsp,
                 Provider<TXStore> txStoreProvider,
                 Provider<VIStore> voStoreProvider,
                 Provider<ClientStore> csp,
                 int maxAllowedNewClientRequests,
                 long agLifetime,
                 long maxAGLifetime,
                 long idTokenLifetime,
                 long maxIDTokenLifetime,
                 long maxATLifetime,
                 long atLifetime,
                 long rtLifetime,
                 long maxRTLifetime,
                 Provider<ClientApprovalStore> casp,
          //       List<MyProxyFacadeProvider> mfp,
                 MailUtilProvider mup,
                 MessagesProvider messagesProvider,
                 Provider<AGIssuer> agip,
                 Provider<ATIssuer> atip,
                 Provider<PAIssuer> paip,
                 Provider<TokenForge> tfp,
                 HashMap<String, String> constants,
                 AuthorizationServletConfig ac,
                 UsernameTransformer usernameTransformer,
                 boolean isPingable,
                 Provider<PermissionsStore> psp,
                 Provider<AdminClientStore> acs,
                 int clientSecretLength,
                 Collection<String> scopes,
                 ClaimSource claimSource,
                 LDAPConfiguration ldapConfiguration2,
                 boolean isRefreshTokenEnabled,
                 boolean twoFactorSupportEnabled,
                 long maxClientRefreshTokenLifetime,
                 JSONWebKeys jsonWebKeys,
                 String issuer,
                 boolean utilServletEnabled,
                 boolean oidcEnabled,
                 CMConfigs cmConfigs,
                 OA2QDLEnvironment qdlEnvironment,
                 boolean rfc8693Enabled,
                 boolean qdlStrictACLs,
                 boolean safeGC,
                 boolean cleanupLockingEnabled,
                 boolean cleanupFailOnErrors,
                 RFC8628ServletConfig rfc8628ServletConfig,
                 boolean rfc8628Enabled,
                 boolean printTSInDebug,
                 long cleanupInterval,
                 Collection<LocalTime> cleanupAlarms,
                 String notifyACEventEmailAddresses,
                 boolean rfc7636Required,
                 boolean demoModeEnabled,
                 long rtGracePeriod,
                 boolean isMonitorEnabled,
                 long monitorInterval,
                 Collection<LocalTime> monitorAlarms,
                 boolean clientCredentialFlowEnabled,
                 MetaDebugUtil debugger,
                 boolean allowPromptNone,
                 DBServiceConfig dbServiceConfig) {

        super(logger,
           //     mfp,
                tsp,
                csp,
                maxAllowedNewClientRequests,
                casp,
                mup,
                messagesProvider,
                agip,
                atip,
                paip,
                tfp,
                constants,
                ac,
                usernameTransformer,
                isPingable,
                psp);
        this.ccfEnabled = clientCredentialFlowEnabled;
        if (0 < agLifetime) {
            this.authorizationGrantLifetime = agLifetime;
        }
        if (0 < atLifetime) {
            this.accessTokenLifetime = atLifetime;
        }
        this.maxAuthorizationGrantLifetime = maxAGLifetime;
        if (clientSecretLength < 0) {
            throw new MyConfigurationException("The client secret length (=" + clientSecretLength + ") is invalid. It must be a positive integer.");
        }
        this.allowPromptNone = allowPromptNone;
        this.clientSecretLength = clientSecretLength;
        this.scopes = scopes;
        this.claimSource = claimSource;
        OA2Scopes.ScopeUtil.setScopes(scopes); //Probably need a better place to do this at some point. Probably.

        this.refreshTokenEnabled = isRefreshTokenEnabled;
        if (this.refreshTokenEnabled) {
            logger.info("Refresh token support enabled");
        } else {
            logger.info("No refresh token support.");
        }

        this.ldapConfiguration2 = ldapConfiguration2;
        this.twoFactorSupportEnabled = twoFactorSupportEnabled;
        this.maxClientRefreshTokenLifetime = maxClientRefreshTokenLifetime;
        this.jsonWebKeys = jsonWebKeys;
        this.issuer = issuer;
        if (claimSource instanceof BasicClaimsSourceImpl) {
            ((BasicClaimsSourceImpl) claimSource).setOa2SE(this);
        }
        this.acs = acs;
        this.utilServletEnabled = utilServletEnabled;
        this.oidcEnabled = oidcEnabled;
        //     this.jsonStoreProvider = jsonStoreProvider;
        this.cmConfigs = cmConfigs;
        this.qdlEnvironment = qdlEnvironment;
        this.rfc8693Enabled = rfc8693Enabled;
        this.txStore = txStoreProvider.get();
        this.VIStore = voStoreProvider.get();
        this.maxIdTokenLifetime = maxIDTokenLifetime;
        this.idTokenLifetime = idTokenLifetime;
        this.maxATLifetime = maxATLifetime;
        this.maxRTLifetime = maxRTLifetime;
        this.qdlStrictACLs = qdlStrictACLs;
        this.safeGC = safeGC;
        this.cleanupLockingEnabled = cleanupLockingEnabled;
        this.rfc8628Enabled = rfc8628Enabled;
        this.printTSInDebug = printTSInDebug;
        this.rfc8628ServletConfig = rfc8628ServletConfig;
        this.cleanupInterval = cleanupInterval;
        this.notifyACEventEmailAddresses = notifyACEventEmailAddresses;
        this.rfc7636Required = rfc7636Required;
        this.demoModeEnabled = demoModeEnabled;
        this.debugger = debugger;
        this.cleanupAlarms = cleanupAlarms;
        this.rtGracePeriod = rtGracePeriod;
        this.monitorInterval = monitorInterval;
        this.monitorAlarms = monitorAlarms;
        this.monitorEnabled = isMonitorEnabled;
        this.cleanupFailOnErrors = cleanupFailOnErrors;
        this.dbServiceConfig = dbServiceConfig;
    }

    public boolean isCleanupFailOnErrors() {
        return cleanupFailOnErrors;
    }

    boolean cleanupFailOnErrors;

    public boolean isMonitorEnabled() {
        return monitorEnabled;
    }

    public void setMonitorEnabled(boolean monitorEnabled) {
        this.monitorEnabled = monitorEnabled;
    }

    public long getMonitorInterval() {
        return monitorInterval;
    }

    public void setMonitorInterval(long monitorInterval) {
        this.monitorInterval = monitorInterval;
    }

    public Collection<LocalTime> getMonitorAlarms() {
        return monitorAlarms;
    }

    public void setMonitorAlarms(Collection<LocalTime> monitorAlarms) {
        this.monitorAlarms = monitorAlarms;
    }

    boolean monitorEnabled;
    long monitorInterval = -1L;
    Collection<LocalTime> monitorAlarms = null;

    public boolean isCleanupLockingEnabled() {
        return cleanupLockingEnabled;
    }

    public void setCleanupLockingEnabled(boolean cleanupLockingEnabled) {
        this.cleanupLockingEnabled = cleanupLockingEnabled;
    }

    boolean cleanupLockingEnabled = false; // default

    public Collection<LocalTime> getCleanupAlarms() {
        return cleanupAlarms;
    }

    Collection<LocalTime> cleanupAlarms;

    public boolean hasCleanupAlarms() {
        return cleanupAlarms != null && (!cleanupAlarms.isEmpty());
    }

    public MetaDebugUtil getDebugger() {
        return debugger;
    }

    public void setDebugger(MetaDebugUtil debugger) {
        this.debugger = debugger;
    }

    MetaDebugUtil debugger;
    boolean demoModeEnabled = false;

    public boolean isDemoModeEnabled() {
        return demoModeEnabled;
    }

    public void setDemoModeEnabled(boolean demoModeEnabled) {
        this.demoModeEnabled = demoModeEnabled;
    }

    public String getNotifyACEventEmailAddresses() {
        return notifyACEventEmailAddresses;
    }

    String notifyACEventEmailAddresses = null;

    public long getCleanupInterval() {
        return cleanupInterval;
    }

    public boolean hasMonitorAlarams() {
        return monitorAlarms != null && !monitorAlarms.isEmpty();
    }

    public boolean hasMonitorInterval() {
        return 0 < monitorInterval;
    }

    long cleanupInterval = -1;

    public RFC8628ServletConfig getRfc8628ServletConfig() {
        return rfc8628ServletConfig;
    }

    RFC8628ServletConfig rfc8628ServletConfig;

    public boolean isPrintTSInDebug() {
        return printTSInDebug;
    }


    boolean printTSInDebug = true;

    public boolean isSafeGC() {
        return safeGC;
    }

    public void setSafeGC(boolean safeGC) {
        this.safeGC = safeGC;
    }

    boolean safeGC = true;

    public boolean isQdlStrictACLs() {
        return qdlStrictACLs;
    }

    boolean qdlStrictACLs = false;
    long maxATLifetime = -1L;

    public long getMaxATLifetime() {
        return maxATLifetime;
    }

    public long getMaxRTLifetime() {
        return maxRTLifetime;
    }

    long maxRTLifetime = -1L;

    VIStore VIStore;

    public VIStore getVIStore() {
        return VIStore;
    }

    public TXStore getTxStore() {
        return txStore;
    }

    public void setTxStore(TXStore txStore) {
        this.txStore = txStore;
    }

    TXStore txStore;

    public OA2QDLEnvironment getQDLEnvironment() {
        return qdlEnvironment;
    }

    public void setQDLEnvironment(OA2QDLEnvironment qdlEnvironment) {
        this.qdlEnvironment = qdlEnvironment;
    }

    OA2QDLEnvironment qdlEnvironment;
    CMConfigs cmConfigs = null;

    public CMConfigs getCmConfigs() {
        return cmConfigs;
    }

    protected Provider<JSONStore> jsonStoreProvider;
    JSONStore<? extends JSONEntry> jsonStore;

    public JSONStore<? extends JSONEntry> getJSONStore() {
        if (jsonStore == null) {
            jsonStore = jsonStoreProvider.get();
        }
        return jsonStore;
    }

    /**
     * Token exchange endpoint
     *
     * @return
     */
    public boolean isRfc8693Enabled() {
        return rfc8693Enabled;
    }

    public void setRfc8693Enabled(boolean rfc8693Enabled) {
        this.rfc8693Enabled = rfc8693Enabled;
    }

    /**
     * Is the client credential flow enabled for this server?
     * @return
     */
    public boolean isCCFEnabled() {
        return ccfEnabled;
    }

    public void setCCFEnabled(boolean ccfEnabled) {
        this.ccfEnabled = ccfEnabled;
    }

    boolean ccfEnabled = true;
    boolean rfc8693Enabled = false;

    /**
     * Device authorization flow endpoints.
     *
     * @return
     */
    public boolean isRfc8628Enabled() {
        return rfc8628Enabled;
    }

    public void setRfc8628Enabled(boolean rfc8628Enabled) {
        this.rfc8628Enabled = rfc8628Enabled;
    }

    boolean rfc8628Enabled = false;

    protected Provider<AdminClientStore> acs;

    AdminClientStore adminClientStore = null;

    public AdminClientStore<AdminClient> getAdminClientStore() {
        if (adminClientStore == null) {
            adminClientStore = acs.get();
        }
        return adminClientStore;
    }

    public boolean isUtilServletEnabled() {
        return utilServletEnabled;
    }

    public void setUtilServletEnabled(boolean utilServletEnabled) {
        this.utilServletEnabled = utilServletEnabled;
    }

    boolean utilServletEnabled = true;


    String issuer;

    public String getIssuer() {
        return issuer;
    }

    public JSONWebKeys getJsonWebKeys() {
        return jsonWebKeys;
    }

    public void setJsonWebKeys(JSONWebKeys jsonWebKeys) {
        this.jsonWebKeys = jsonWebKeys;
    }

    protected JSONWebKeys jsonWebKeys;

    public boolean isTwoFactorSupportEnabled() {
        return twoFactorSupportEnabled;
    }

    public long getMaxClientRefreshTokenLifetime() {
        return maxClientRefreshTokenLifetime;
    }

    long maxIdTokenLifetime = 0L;
    long idTokenLifetime = 0L;

    public long getMaxIdTokenLifetime() {
        return maxIdTokenLifetime;
    }

    /**
     * Get the configured default ID token lifetime for the server
     *
     * @return
     */
    public long getIdTokenLifetime() {
        return idTokenLifetime;
    }

    long maxClientRefreshTokenLifetime = 0L;

    boolean twoFactorSupportEnabled = false;
    boolean refreshTokenEnabled = false;

    public boolean isRefreshTokenEnabled() {
        return refreshTokenEnabled;
    }

    public void setRefreshTokenEnabled(boolean refreshTokenEnabled) {
        this.refreshTokenEnabled = refreshTokenEnabled;
    }


    int clientSecretLength = 64; // default in spec. see OAUTH-215

    public int getClientSecretLength() {
        return clientSecretLength;
    }

    protected ClaimSource claimSource;
    Collection<String> scopes;

    /**
     * The scopes this server currently supports.
     *
     * @return
     */
    public Collection<String> getScopes() {
        return scopes;
    }

    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    public ClaimSource getClaimSource() {
        return claimSource;
    }

    public void setClaimSource(ClaimSource claimSource) {
        this.claimSource = claimSource;
    }

    public boolean hasScopeHandler() {
        return claimSource != null;
    }

    public LDAPConfiguration getLdapConfiguration() {
        return ldapConfiguration2;
    }

    public void setLdapConfiguration(LDAPConfiguration ldapConfiguration2) {
        this.ldapConfiguration2 = ldapConfiguration2;
    }


    LDAPConfiguration ldapConfiguration2;


    /**
     * Returns <code>true</code> if this server has OIDC support enabled.
     *
     * @return
     */
    public boolean isOIDCEnabled() {
        return oidcEnabled;
    }

    boolean oidcEnabled = true;

    long accessTokenLifetime = ACCESS_TOKEN_LIFETIME_DEFAULT;

    /**
     * Get the configured default access token lifetime for the server
     *
     * @return
     */
    public long getAccessTokenLifetime() {
        return accessTokenLifetime;
    }

    public void setAccessTokenLifetime(long accessTokenLifetime) {
        this.accessTokenLifetime = accessTokenLifetime;
    }

    public void setRefreshTokenLifetime(long refreshTokenLifetime) {
        this.refreshTokenLifetime = refreshTokenLifetime;
    }

    long refreshTokenLifetime = REFRESH_TOKEN_LIFETIME_DEFAULT;

    /**
     * Get the configured default refresh token lifetime for the server
     *
     * @return
     */
    public long getRefreshTokenLifetime() {
        return refreshTokenLifetime;
    }


    // This is a nod towards allowing device flow clients to set their df lifetimes.
    // not used yet.
    public long getMaxAuthorizationGrantLifetime() {
        return maxAuthorizationGrantLifetime;
    }

    long maxAuthorizationGrantLifetime;

    public long getAuthorizationGrantLifetime() {
        return authorizationGrantLifetime;
    }

    public void setAuthorizationGrantLifetime(long authorizationGrantLifetime) {
        this.authorizationGrantLifetime = authorizationGrantLifetime;
    }

    long authorizationGrantLifetime = AUTHORIZATION_GRANT_LIFETIME_DEFAULT;

    /**
     * Given the client id, look up the admin and determine what (if any) the VI is.
     * The returned value may be null,, meaning there is no VI.
     * If the VI is disabled, it will not be returned either.<br/><br/>
     * This has its own call here because it involves multiple store lookups. It cannot
     * be done as a join in SQL or some such because there are no guarantees the stores
     * are all SQL -- some may be file stores or even in another unrelated database.
     *
     * @param clientID
     * @return
     */
    public VirtualIssuer getVI(Identifier clientID) {
        if (clientID == null) {
            return null; // should not happen.
        }
        List<Identifier> adminIDs = getPermissionStore().getAdmins(clientID);
        if (adminIDs == null || adminIDs.isEmpty()) {
            return null; // happens for every unmanaged client.
        }
        switch (adminIDs.size()) {
            case 0:
                return null;
            case 1:
                AdminClient ac = getAdminClientStore().get(adminIDs.get(0));
                if (ac == null || ac.getVirtualIssuer() == null) {
                    return null; // no VO set. Most common case.
                }
                DebugUtil.trace(this, "got admin client " + ac.getIdentifierString());
                VirtualIssuer vi = (VirtualIssuer) getVIStore().get(ac.getVirtualIssuer());
                DebugUtil.trace(this, "got vi  " + (vi == null ? "(none)" : vi.getIdentifierString()));
                if (vi == null) {
                    return null;
                }
                if (!vi.isValid()) {
                    throw new GeneralException("invalid virtual issuer \"" + vi.getIdentifierString() + "\"");
                }
                return vi;
            case 2:
                throw new NFWException("too many admins for this client.");
        }
        return null;
    }

    @Override
    public List<Store> listStores() {
        List<Store> stores = super.listStores();
        stores.add(getTxStore());
        stores.add(getVIStore());
        return stores;
    }

    public boolean isRfc7636Required() {
        return rfc7636Required;
    }

    public void setRfc7636Required(boolean rfc7636Required) {
        this.rfc7636Required = rfc7636Required;
    }

    boolean rfc7636Required = false;

    public long getRtGracePeriod() {
        return rtGracePeriod;
    }

    public void setRtGracePeriod(long rtGracePeriod) {
        this.rtGracePeriod = rtGracePeriod;
    }

    long rtGracePeriod = -1L;

    public boolean isRTGracePeriodEnabled() {
        return rtGracePeriod != OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DISABLED;
    }

    public boolean isUseProxyForCerts() {
        return useProxyForCerts;
    }

    public void setUseProxyForCerts(boolean useProxyForCerts) {
        this.useProxyForCerts = useProxyForCerts;
    }

    boolean useProxyForCerts = false;
   protected  List<Store> storeList = null;

    /**
     * A list of all stores. This is used in bootstrapping the system and initializing it.
     * @return
     */

    public List<Store> getAllStores() {
        if (storeList == null) {
            storeList = new ArrayList<>();
            //Note that the admins then the clients should always come first.
            // To extend this, append to it.
            storeList.add(getAdminClientStore());
            storeList.add(getClientStore());
            storeList.add(getClientApprovalStore());
            storeList.add(getPermissionStore());
            storeList.add(getVIStore());
            storeList.add(getTransactionStore());
            storeList.add(getTxStore());
        }
        return storeList;
    }

    /**
     * Allow prompt = none parameter in OIDC clients. https://github.com/ncsa/oa4mp/issues/236.
     * This should be configurable.
     * @return
     */
    public boolean isAllowPromptNone() {
        return allowPromptNone;
    }

    public void setAllowPromptNone(boolean allowPromptNone) {
        this.allowPromptNone = allowPromptNone;
    }

    boolean allowPromptNone = false;

    public DBServiceConfig getDBServiceConfig() {
        return dbServiceConfig;
    }

    DBServiceConfig dbServiceConfig = null;
}
