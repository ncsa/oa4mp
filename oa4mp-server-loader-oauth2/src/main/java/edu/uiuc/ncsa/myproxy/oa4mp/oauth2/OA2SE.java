package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CMConfigs;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628ServletConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VOStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2QDLEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;

import javax.inject.Provider;
import java.time.LocalTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader.AUTHORIZATION_GRANT_LIFETIME_DEFAULT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/14 at  4:16 PM
 */
public class OA2SE extends ServiceEnvironmentImpl {
    public OA2SE(MyLoggingFacade logger,
                 Provider<TransactionStore> tsp,
                 Provider<TXStore> txStoreProvider,
                 Provider<VOStore> voStoreProvider,
                 Provider<ClientStore> csp,
                 int maxAllowedNewClientRequests,
                 long agLifetime,
                 long maxAGLifetime,
                 long idTokenLifetime,
                 long maxIDTokenLifetime,
                 long maxATLifetime,
                 long atLifetime,
                 long maxRTLifetime,
                 Provider<ClientApprovalStore> casp,
                 List<MyProxyFacadeProvider> mfp,
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
               //  Provider<JSONStore> jsonStoreProvider,
                 CMConfigs cmConfigs,
                 OA2QDLEnvironment qdlEnvironment,
                 boolean rfc8693Enabled,
                 boolean qdlStrictACLs,
                 boolean safeGC,
                 RFC8628ServletConfig rfc8628ServletConfig,
                 boolean rfc8628Enabled,
                 boolean printTSInDebug,
                 long cleanupInterval,
                 Collection<LocalTime> cleanupAlarms,
                 String notifyACEventEmailAddresses,
                 boolean rfc7636Required,
                 boolean demoModeEnabled,
                 MetaDebugUtil debugger) {

        super(logger,
                mfp,
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
        if (0 < agLifetime) {
            this.authorizationGrantLifetime = agLifetime;
        }
        if (0 < atLifetime) {
            this.accessTokenLifetime = atLifetime;
        }
         this.maxAuthorizationGrantLifetime = maxAGLifetime;
        if (clientSecretLength < 0) {
            throw new MyConfigurationException("Error: The client secret length (=" + clientSecretLength + ") is invalid. It must be a positive integer.");
        }
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
            DebugUtil.trace(this, "***Setting runtime environment in the scope handler:" + claimSource.getClass().getSimpleName());
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
        this.voStore = voStoreProvider.get();
        this.maxIdTokenLifetime = maxIDTokenLifetime;
        this.idTokenLifetime = idTokenLifetime;
        this.maxATLifetime = maxATLifetime;
        this.maxRTLifetime = maxRTLifetime;
        this.qdlStrictACLs = qdlStrictACLs;
        this.safeGC = safeGC;
        this.rfc8628Enabled = rfc8628Enabled;
        this.printTSInDebug = printTSInDebug;
        this.rfc8628ServletConfig = rfc8628ServletConfig;
        this.cleanupInterval = cleanupInterval;
        this.notifyACEventEmailAddresses = notifyACEventEmailAddresses;
        this.rfc7636Required = rfc7636Required;
        this.demoModeEnabled = demoModeEnabled;
        this.debugger = debugger;
        this.cleanupAlarms = cleanupAlarms;
    }

    public Collection<LocalTime> getCleanupAlarms() {
        return cleanupAlarms;
    }

    Collection<LocalTime> cleanupAlarms;
    public boolean hasCleanupAlarms(){
        return cleanupAlarms!= null && (!cleanupAlarms.isEmpty());
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

    VOStore voStore;

    public VOStore getVOStore() {
        return voStore;
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


    /**
     * The default if nothing is specified is 15 days.
     *
     * @return
     * @deprecated This was badly named. Use {@link #getMaxRTLifetime()}
     */
    public long getRefreshTokenLifetime() {
        return getMaxRTLifetime();
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

    // TODO make this configurable.

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

    public long getAccessTokenLifetime() {
        return accessTokenLifetime;
    }

    public void setAccessTokenLifetime(long accessTokenLifetime) {
        this.accessTokenLifetime = accessTokenLifetime;
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
     * Given the client id, look up the admin and determine what (if any) the VO is.
     * The returned value may be null,, meaning there is no VO.
     * If the VO is disabled, it will not be returned either.<br/><br/>
     * This has its own call here because it involves multiple store lookups. It cannot
     * be done as a join in SQL or some such because there are no guarantees the stores
     * are all SQL -- some may be file stores or even in another unrelated database.
     *
     * @param clientID
     * @return
     */
    public VirtualOrganization getVO(Identifier clientID) {
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
                if (ac == null || ac.getVirtualOrganization() == null) {
                    return null; // no VO set. Most common case.
                }
                DebugUtil.trace(this, "got admin client " + ac.getIdentifierString());
                VirtualOrganization vo = (VirtualOrganization) getVOStore().get(ac.getVirtualOrganization());
                DebugUtil.trace(this, "got vo  " + (vo == null ? "(none)" : vo.getIdentifierString()));
                if (vo != null && vo.isValid()) {
                    return vo;
                } else {
                    return null;
                }
            case 2:
                throw new NFWException("Error: too many admins for this client.");
        }
        return null;
    }

    @Override
    public List<Store> listStores() {
        List<Store> stores = super.listStores();
        stores.add(getTxStore());
        stores.add(getVOStore());
        return stores;
    }

    public boolean isRfc7636Required() {
        return rfc7636Required;
    }

    public void setRfc7636Required(boolean rfc7636Required) {
        this.rfc7636Required = rfc7636Required;
    }

    boolean rfc7636Required = false;

}
