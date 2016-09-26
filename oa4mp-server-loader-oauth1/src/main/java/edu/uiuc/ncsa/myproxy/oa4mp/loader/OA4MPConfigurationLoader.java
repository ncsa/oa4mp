package edu.uiuc.ncsa.myproxy.oa4mp.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.security.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_1_0a.OAuthConstants;
import edu.uiuc.ncsa.security.oauth_1_0a.OAuthTokenForge;
import edu.uiuc.ncsa.security.oauth_1_0a.client.OAClientProvider;
import edu.uiuc.ncsa.security.oauth_1_0a.server.AGIProvider;
import edu.uiuc.ncsa.security.oauth_1_0a.server.ATIProvider;
import edu.uiuc.ncsa.security.oauth_1_0a.server.PAIProvider;
import net.oauth.OAuth;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.util.OA4MPIdentifierProvider.*;

/**
 * This made to be over-ridden and extended with new features, hence the separate call for
 * creating the service environment. All of the elements are protected rather than private.
 * <H3>Usage</H3>
 * <UL>
 * <LI>Extend this, adding in new extensions to the XML configuration</LI>
 * <LI>Choose a servlet (such as Init) which has to be loaded first, using Tomcat's load-on-startup parameter</LI>
 * <LI>Set an instance of this as the Bootstrapper by over-riding {@link edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet} loadEnvironment
 * and setting the instance directly. This side-steps Tomcat's loading issues and Java single inheritance limitations at once</LI>
 * <p/>
 * </UL>
 */
public class OA4MPConfigurationLoader<T extends ServiceEnvironmentImpl> extends AbstractConfigurationLoader<T> {
    @Override
    public String getVersionString() {
        return "OA4MP server configuration loader, version " + VERSION_NUMBER;
    }

    @Override
    public Provider<AGIssuer> getAGIProvider() {
        return new AGIProvider(getTokenForgeProvider().get(), getServiceAddress());
    }

    @Override
    public Provider<ClientStore> getClientStoreProvider() {
        return getCSP();
    }

    @Override
    public Provider<ClientApprovalStore> getClientApprovalStoreProvider() {
        return getCASP();
    }

    @Override
    public Provider<TransactionStore> getTransactionStoreProvider() {
        return getTSP();
    }

    @Override
    public Provider<TokenForge> getTokenForgeProvider() {
        return new OAuthForgeProvider();
    }

    @Override
    public Provider<ATIssuer> getATIProvider() {
        return new ATIProvider(getTokenForgeProvider().get(), getServiceAddress());
    }

    @Override
    public Provider<PAIssuer> getPAIProvider() {
        return new PAIProvider(getTokenForgeProvider().get(), getServiceAddress());
    }

    public OA4MPConfigurationLoader(ConfigurationNode node) {
        super(node);
   }

    public OA4MPConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public IdentifiableProvider<? extends Client> getClientProvider() {
        // Do *not* use timestamps when making these, since this would be redundant.
        return new OAClientProvider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, CLIENT_ID, false));
    }

    protected static class OAuthForgeProvider implements Provider<TokenForge>{
        public TokenForge get(){
            return new OAuthTokenForge("myproxy:oa4mp,2012:oauth1:");
        }
    }

    HashMap<String,String> constants;

    @Override
    public HashMap<String, String> getConstants() {
        if(constants == null){
            constants = new HashMap<String, String>();
            // OAuth 1.0a callback constant. This is used to as a key for http request parameters
            constants.put(ServiceConstantKeys.CALLBACK_URI_KEY, OAuthConstants.OAUTH_CALLBACK);
            constants.put(ServiceConstantKeys.TOKEN_KEY, OAuth.OAUTH_TOKEN);
            constants.put(ServiceConstantKeys.FORM_ENCODING_KEY, OAuthConstants.FORM_ENCODING);
            constants.put(ServiceConstantKeys.CERT_REQUEST_KEY, "certreq");
            constants.put(ServiceConstantKeys.CERT_LIFETIME_KEY, "certlifetime");
            constants.put(ServiceConstantKeys.CONSUMER_KEY, OAuthConstants.OAUTH_CONSUMER_KEY);
         }
        return constants;
    }
}