package edu.uiuc.ncsa.co.loader;

import edu.uiuc.ncsa.co.ldap.LDAPEntry;
import edu.uiuc.ncsa.co.ldap.LDAPStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyFacadeProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;

import javax.inject.Provider;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  4:14 PM
 */
public class COSE extends OA2SE {
    public COSE(MyLoggingFacade logger,
                Provider<TransactionStore> tsp,
                Provider<ClientStore> csp,
                int maxAllowedNewClientRequests,
                long rtLifetime, Provider<ClientApprovalStore> casp,
                List<MyProxyFacadeProvider> mfp,
                MailUtilProvider mup,
                MessagesProvider messagesProvider,
                Provider<AGIssuer> agip, Provider<ATIssuer> atip,
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
                ScopeHandler scopeHandler,
                LDAPConfiguration ldapConfiguration2,
                boolean isRefreshTokenEnabled,
                boolean twoFactorSupportEnabled,
                long maxClientRefreshTokenLifetime,
                Provider<LDAPStore> mldap,
                JSONWebKeys signingKeyPair) {
        super(logger,
                tsp,
                csp,
                maxAllowedNewClientRequests,
                rtLifetime,
                casp,
                mfp,
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
                psp,
                acs,
                clientSecretLength,
                scopes,
                scopeHandler,
                ldapConfiguration2,
                isRefreshTokenEnabled,
                twoFactorSupportEnabled,
                maxClientRefreshTokenLifetime,
                signingKeyPair);
        this.mldap = mldap;
        if(scopeHandler instanceof BasicScopeHandler){
            DebugUtil.dbg(this,"***Setting runtime environment in the scope handler:" + scopeHandler.getClass().getSimpleName());
            ((BasicScopeHandler)scopeHandler).setOa2SE(this);
        }
    }

    Provider<LDAPStore> mldap;
    LDAPStore ldapStore = null;

    public LDAPStore<LDAPEntry> getLDAPStore() {
        if (ldapStore == null) {
            ldapStore = mldap.get();
        }
        return ldapStore;
    }
}
