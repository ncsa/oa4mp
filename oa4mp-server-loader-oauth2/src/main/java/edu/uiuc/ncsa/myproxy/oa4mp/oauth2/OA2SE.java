package edu.uiuc.ncsa.myproxy.oa4mp.oauth2;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.BasicClaimsSourceImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CMConfigs;
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
                 Provider<ClientStore> csp,
                 int maxAllowedNewClientRequests,
                 long rtLifetime,
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
                 QDLEnvironment qdlEnvironment) {
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
        if (0 < rtLifetime) {
            this.rtLifetime = rtLifetime;
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
            DebugUtil.dbg(this, "***Setting runtime environment in the scope handler:" + claimSource.getClass().getSimpleName());
            ((BasicClaimsSourceImpl) claimSource).setOa2SE(this);
        }
        this.acs = acs;
        this.utilServletEnabled = utilServletEnabled;
        this.oidcEnabled = oidcEnabled;
        this.jsonStoreProvider = jsonStoreProvider;
        this.cmConfigs = cmConfigs;
        this.qdlEnvironment = qdlEnvironment;
    }

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

    long rtLifetime = 15 * 24 * 3600 * 1000L; // default is 15 days.

    /**
     * The default if nothing is specified is 15 days.
     *
     * @return
     */
    public long getRefreshTokenLifetime() {
        return rtLifetime;
    }

    int clientSecretLength = 64; // default in spec. see OAUTH-215

    public int getClientSecretLength() {
        return clientSecretLength;
    }

    protected ClaimSource claimSource;
    Collection<String> scopes;

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
}
