package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CMConfigs;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.qdl.config.QDLEnvironment;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/14 at  4:16 PM
 */
public class OA2SE extends ServiceEnvironmentImpl {
    public OA2SE(MyLoggingFacade logger,
                 Provider<TransactionStore> tsp,
                 Provider<TXStore> txStoreProvider,
                 Provider<ClientStore> csp,
                 int maxAllowedNewClientRequests,
                 long agLifetime,
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
                 Provider<JSONStore> jsonStoreProvider,
                 CMConfigs cmConfigs,
                 QDLEnvironment qdlEnvironment,
                 boolean rfc8693Enabled,
                 boolean qdlStrictACLs,
                 boolean safeGC,
                 boolean rfc8628Enabled) {
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
        if(0 < agLifetime){
            this.authorizationGrantLifetime = agLifetime;
        }
        if(0 < atLifetime){
            this.accessTokenLifetime = atLifetime;
        }

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
        //   this.mldap = mldap;
        if (claimSource instanceof BasicClaimsSourceImpl) {
            DebugUtil.trace(this, "***Setting runtime environment in the scope handler:" + claimSource.getClass().getSimpleName());
            ((BasicClaimsSourceImpl) claimSource).setOa2SE(this);
        }
        this.acs = acs;
        this.utilServletEnabled = utilServletEnabled;
        this.oidcEnabled = oidcEnabled;
        this.jsonStoreProvider = jsonStoreProvider;
        this.cmConfigs = cmConfigs;
        this.qdlEnvironment = qdlEnvironment;
        this.rfc8693Enabled = rfc8693Enabled;
        this.txStore = txStoreProvider.get();
        this.maxATLifetime = maxATLifetime;
        this.maxRTLifetime = maxRTLifetime;
        this.qdlStrictACLs = qdlStrictACLs;
        this.safeGC = safeGC;
        this.rfc8628Enabled = rfc8628Enabled;
    }

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

    public TXStore getTxStore() {
        return txStore;
    }

    public void setTxStore(TXStore txStore) {
        this.txStore = txStore;
    }

    TXStore txStore;
    public QDLEnvironment getQDLEnvironment() {
        return qdlEnvironment;
    }

    public void setQDLEnvironment(QDLEnvironment qdlEnvironment) {
        this.qdlEnvironment = qdlEnvironment;
    }

    QDLEnvironment qdlEnvironment;
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

    //FIXME Default.
    long accessTokenLifetime = 15*60*1000L;

    public long getAccessTokenLifetime() {
        return accessTokenLifetime;
    }
    public void setAccessTokenLifetime(long accessTokenLifetime){
        this.accessTokenLifetime = accessTokenLifetime;
    }

    public long getAuthorizationGrantLifetime() {
        return authorizationGrantLifetime;
    }

    public void setAuthorizationGrantLifetime(long authorizationGrantLifetime) {
        this.authorizationGrantLifetime = authorizationGrantLifetime;
    }

    long authorizationGrantLifetime = 15*60*1000L;
}
