package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.HierarchicalConfigProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.servlet.TrivialUsernameTransformer;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.mail.MailUtil;
import edu.uiuc.ncsa.security.util.mail.MailUtilProvider;
import edu.uiuc.ncsa.security.util.pkcs.KeyPairQueue;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.net.URI;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet.RETRY_MESSAGE;


/**
 * The runtime environment for a service. This is a bridge between the configuration and the instances.
 * Typically it is populated with providers (i.e.configured factories) which retrieves the instances
 * as needed.
 * <p>Created by Jeff Gaynor<br>
 * on 1/9/12 at  4:08 PM
 */
public class ServiceEnvironmentImpl extends MyProxyServiceEnvironment implements ServiceEnvironment {

    public KeyPairQueue getKeyPairQueue() {
        return kpq;
    }

    KeyPairQueue kpq = new KeyPairQueue();

    public KeyPair getKeyPair() {
        return kpq.pop();
    }

    AuthorizationServletConfig authorizationServletConfig;

    public AuthorizationServletConfig getAuthorizationServletConfig() {
        return authorizationServletConfig;
    }

    AGIssuer agIssuer;
    URI serviceAddress;

    @Override
    public URI getServiceAddress() {
        return serviceAddress;
    }

    public void setServiceAddress(URI serviceAddress) {
        this.serviceAddress = serviceAddress;
    }

    @Override
    public AGIssuer getAgIssuer() {
        if (agIssuer == null) {
            agIssuer = agip.get();
        }
        return agIssuer;
    }

    ATIssuer atIssuer;

    @Override
    public ATIssuer getAtIssuer() {
        if (atIssuer == null) {
            atIssuer = atip.get();
        }
        return atIssuer;
    }

    @Override
    public PAIssuer getPaIssuer() {
        if (paIssuer == null) {
            paIssuer = paip.get();
        }
        return paIssuer;
    }

    PAIssuer paIssuer;

    @Override
    public TokenForge getTokenForge() {
        return tfp.get();
    }

    public static class MessagesProvider extends HierarchicalConfigProvider<Map<String, String>> {

        public MessagesProvider(ConfigurationNode config) {
            super(config);
        }

        @Override
        protected boolean checkEvent(CfgEvent cfgEvent) {
            if (cfgEvent.getConfiguration().getName().equals("messages")) {
                setConfig(cfgEvent.getConfiguration());
                return true;
            }
            return false;
        }

        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            if (checkEvent(configurationEvent)) {
                return get();
            }
            return null;
        }

        @Override
        public Map<String, String> get() {
            HashMap<String, String> messages = new HashMap<String, String>();
            messages.put(RETRY_MESSAGE, Configurations.getNodeValue(getConfig(), RETRY_MESSAGE, "Authentication failed."));
            return messages;
        }
    }


    public ServiceEnvironmentImpl(MyLoggingFacade logger,
                                  List<MyProxyFacadeProvider> mfp,
                                  Provider<TransactionStore> tsp,
                                  Provider<ClientStore> csp,
                                  int maxAllowedNewClientRequests,
                                  Provider<ClientApprovalStore> casp,
                                  MailUtilProvider mup,
                                  MessagesProvider messagesProvider,
                                  Provider<AGIssuer> agip,
                                  Provider<ATIssuer> atip,
                                  Provider<PAIssuer> paip,
                                  Provider<TokenForge> tfp,
                                  HashMap<String,String> constants,
                                  AuthorizationServletConfig ac,
                                  UsernameTransformer usernameTransformer,
                                  boolean isPingable) {
        super(logger, mfp, constants);
        this.casp = casp;
        this.csp = csp;
        this.tsp = tsp;
        this.mup = mup;
        this.messagesProvider = messagesProvider;
        this.atip = atip;
        this.agip = agip;
        this.paip = paip;
        this.tfp = tfp;
        this.authorizationServletConfig = ac;
        this.maxAllowedNewClientRequests = maxAllowedNewClientRequests;
        this.usernameTransformer = usernameTransformer;
        setPingable(isPingable);
    }

    MessagesProvider messagesProvider;


    protected Provider<TransactionStore> tsp;
    protected Provider<ClientStore> csp;
    protected Provider<ClientApprovalStore> casp;
    protected Provider<AGIssuer> agip;
    protected Provider<ATIssuer> atip;
    protected Provider<PAIssuer> paip;
    protected Provider<TokenForge> tfp;



    Map<String, String> messages;

    @Override
    public Map<String, String> getMessages() {
        if (messages == null) {
            if (messagesProvider == null) {
                messages = new HashMap<String, String>();
                messages.put(RETRY_MESSAGE, "Authentication failed.");
            } else {
                messages = messagesProvider.get();
            }
        }
        return messages;
    }

    @Override
    public ClientApprovalStore getClientApprovalStore() {
        if (clientApprovalStore == null) {
            clientApprovalStore = casp.get();
        }
        return clientApprovalStore;
    }

    @Override
    public ClientStore getClientStore() {
        if (clientStore == null) {
            clientStore = csp.get();
        }
        return clientStore;
    }

    protected MailUtil mailUtil;
    protected ClientApprovalStore<ClientApproval> clientApprovalStore;
    protected ClientStore clientStore;
    protected TransactionStore<ServiceTransaction> transactionStore;
    MailUtilProvider mup;

    @Override
    public MailUtil getMailUtil() {
        if (mailUtil == null) {
            mailUtil = mup.get();
        }
        return mailUtil;
    }




    @Override
    public TransactionStore<ServiceTransaction> getTransactionStore() {
        if (transactionStore == null) {
            transactionStore = (TransactionStore<ServiceTransaction>) tsp.get();
        }
        return transactionStore;
    }

    public boolean isPollingEnabled() {
        return clientApprovalThread != null;
    }

    public AbstractCLIApprover.ClientApprovalThread getClientApprovalThread() {
        return clientApprovalThread;
    }

    public void setClientApprovalThread(AbstractCLIApprover.ClientApprovalThread clientApprovalThread) {
        this.clientApprovalThread = clientApprovalThread;
    }

    AbstractCLIApprover.ClientApprovalThread clientApprovalThread;

    int maxAllowedNewClientRequests = 100;

    @Override
    public int getMaxAllowedNewClientRequests() {
        return maxAllowedNewClientRequests;
    }

    UsernameTransformer usernameTransformer = new TrivialUsernameTransformer();

    /**
     * Use the setter to customize the user name transformation.
     * @return
     */
    public UsernameTransformer getUsernameTransformer(){
      return usernameTransformer;
    }

    public void setUsernameTransformer(UsernameTransformer usernameTransformer){
        this.usernameTransformer = usernameTransformer;
    }

}
