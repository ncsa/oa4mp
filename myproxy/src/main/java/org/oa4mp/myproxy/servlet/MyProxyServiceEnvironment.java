package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.server.issuers.AGIssuer;
import org.oa4mp.delegation.server.issuers.ATIssuer;
import org.oa4mp.delegation.server.issuers.PAIssuer;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.server.api.storage.servlet.AuthorizationServletConfig;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.cm.CMConfigs;
import org.oa4mp.server.loader.oauth2.servlet.DIServiceConfig;
import org.oa4mp.server.loader.oauth2.servlet.RFC8628ServletConfig;
import org.oa4mp.server.loader.oauth2.storage.tx.TXStore;
import org.oa4mp.server.loader.qdl.scripting.OA2QDLEnvironment;

import javax.inject.Provider;
import java.time.LocalTime;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

/**
 * An environment that needs to have my proxy services available.
 * <p>Created by Jeff Gaynor<br>
 * on 9/4/15 at  11:00 AM
 */
public class MyProxyServiceEnvironment extends OA2SE {

    public MyProxyServiceEnvironment(MyLoggingFacade logger,
                                     Provider<TransactionStore> tsp,
                                     Provider<TXStore> txStoreProvider,
                                     Provider<org.oa4mp.server.loader.oauth2.storage.vi.VIStore> voStoreProvider,
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
                                     DIServiceConfig DIServiceConfig,
                                     List<MyProxyFacadeProvider> mfp
    ) {
        super(
                logger,
                tsp,
                txStoreProvider,
                voStoreProvider,
                csp,
                maxAllowedNewClientRequests,
                agLifetime,
                maxAGLifetime,
                idTokenLifetime,
                maxIDTokenLifetime,
                maxATLifetime,
                atLifetime,
                rtLifetime,
                maxRTLifetime,
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
                psp,
                acs,
                clientSecretLength,
                scopes,
                claimSource,
                ldapConfiguration2,
                isRefreshTokenEnabled,
                twoFactorSupportEnabled,
                maxClientRefreshTokenLifetime,
                jsonWebKeys,
                issuer,
                utilServletEnabled,
                oidcEnabled,
                cmConfigs,
                qdlEnvironment,
                rfc8693Enabled,
                qdlStrictACLs,
                safeGC,
                cleanupLockingEnabled,
                cleanupFailOnErrors,
                rfc8628ServletConfig,
                rfc8628Enabled,
                printTSInDebug,
                cleanupInterval,
                cleanupAlarms,
                notifyACEventEmailAddresses,
                rfc7636Required,
                demoModeEnabled,
                rtGracePeriod,
                isMonitorEnabled,
                monitorInterval,
                monitorAlarms,
                clientCredentialFlowEnabled,
                debugger,
                allowPromptNone,
                DIServiceConfig
        );
        this.mfps = mfp;

    }

    List<MyProxyFacadeProvider> mfps;

    protected List<MyProxyServiceFacade> myProxyServices;

    public List<MyProxyServiceFacade> getMyProxyServices() {
        if (myProxyServices == null) {
            myProxyServices = new LinkedList<MyProxyServiceFacade>();
            // loop through each found component
            for (MyProxyFacadeProvider m : mfps) {
                myProxyServices.add(m.get());
            }
            return myProxyServices;
        }
        return myProxyServices;
    }
}
