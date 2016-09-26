package edu.uiuc.ncsa.myproxy.oa4mp.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_1_0a.OAuthConstants;
import edu.uiuc.ncsa.security.oauth_1_0a.OAuthTokenForge;
import edu.uiuc.ncsa.security.oauth_1_0a.OAuthUtilities;
import edu.uiuc.ncsa.security.oauth_1_0a.client.DelegationServiceImplProvider;
import edu.uiuc.ncsa.security.oauth_1_0a.client.OAClient;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.ssl.VerifyingHTTPClientFactory;
import net.oauth.OAuth;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment.CALLBACK_URI_KEY;

/**
 * Referenced in the deployment descriptor, this class will process the configuration file and return
 * a {@link edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment}.
 * <p>Created by Jeff Gaynor<br>
 * on 3/23/12 at  8:04 AM
 */
public class ClientLoader<T extends ClientEnvironment> extends AbstractClientLoader<T>{
    @Override
    public String getVersionString() {
        return "OA4MP Client configuration loader, version " + VERSION_NUMBER;
    }

    public ClientLoader(ConfigurationNode configurationNode) {
        super(configurationNode);
    }


    /**
     * Factory method. Override this to create the actual instance as needed.
     *
     * @param tokenForgeProvider
     * @param clientProvider
     * @param constants
     * @return
     */
    public T createInstance(Provider<TokenForge> tokenForgeProvider,
                            Provider<Client> clientProvider,
                            HashMap<String, String> constants) {
        ClientEnvironment ce = null;
        try {
            ce = new ClientEnvironment(
                    myLogger, constants,
                    getAccessTokenURI(),
                    getAuthorizeURI(),
                    getCallback(),
                    getInitiateURI(),
                    getAssetURI(),
                    checkCertLifetime(),
                    getId(),
                    checkPrivateKey(),
                    checkPublicKey(),
                    getSkin(),
                    isEnableAssetCleanup(),
                    getMaxAssetLifetime(),
                    getKeypairLifetime(),
                    getAssetProvider(),
                    clientProvider,
                    tokenForgeProvider,
                    getDSP(),
                    getAssetStoreProvider(),
                    isShowRedirectPage(),
                    getErrorPagePath(),
                    getRedirectPagePath(),
                    getSuccessPagePath()
            );
        } catch (IOException e) {
            throw new MyConfigurationException("Error; Could not configure environment", e);
        }
        init();
        return (T) ce;
    }


    protected void init(){
        VerifyingHTTPClientFactory clientFactory = new VerifyingHTTPClientFactory(myLogger, getSSLConfiguration());
        OAuthUtilities.setClientFactory(clientFactory);
    }

    AssetProvider assetProvider;
    @Override
    public AssetProvider getAssetProvider() {
        if(assetProvider == null){
            assetProvider = new AssetProvider();
        }
        return assetProvider;
    }

    protected boolean isShowRedirectPage(){
        String temp = getCfgValue(ClientXMLTags.SHOW_REDIRECT_PAGE);
        if(temp == null || temp.length() == 0) return false;
        return Boolean.parseBoolean(getCfgValue(ClientXMLTags.SHOW_REDIRECT_PAGE));
    }

    protected String getErrorPagePath(){
        return getCfgValue(ClientXMLTags.ERROR_PAGE_PATH);
    }
    protected String getSuccessPagePath(){
        return getCfgValue(ClientXMLTags.SUCCESS_PAGE_PATH);
    }
    protected String getRedirectPagePath(){
        return getCfgValue(ClientXMLTags.REDIRECT_PAGE_PATH);
    }

    @Override
    public T createInstance() {

        Provider<TokenForge> tokenForgeProvider = new Provider<TokenForge>() {
            @Override
            public TokenForge get() {
                return new OAuthTokenForge(getId());
            }
        };

        Provider<Client> clientProvider = new Provider<Client>() {
            @Override
            public Client get() {
                OAClient c = new OAClient(BasicIdentifier.newID(getId()));
                c.setSignatureMethod(OAuthConstants.RSA_SHA1);
                c.setCreationTS(new Date());
                return c;
            }
        };

        // sets constants specific to this protocol.
        HashMap<String, String> constants = new HashMap<String, String>();
        constants.put(CALLBACK_URI_KEY, OAuthConstants.OAUTH_CALLBACK);
        constants.put(ClientEnvironment.FORM_ENCODING, "UTF-8");
        constants.put(ClientEnvironment.TOKEN, OAuth.OAUTH_TOKEN);
        constants.put(ClientEnvironment.VERIFIER, OAuth.OAUTH_VERIFIER);

        return createInstance(tokenForgeProvider, clientProvider, constants);
    }

    protected PrivateKey checkPrivateKey() throws IOException {
        String privateKeyFileName = getCfgValue(ClientXMLTags.PRIVATE_KEY);
        if (trivial(privateKeyFileName)) {
            throw new MyConfigurationException("Error: There is no private key specified.");
        }
        File privateKeyFile = new File(privateKeyFileName);
        if (!privateKeyFile.exists()) {
            throw new MyConfigurationException("Error: The specified private key file \"" + privateKeyFileName + "\" does not exist");
        }
        if (!privateKeyFile.isFile()) {
            throw new MyConfigurationException("Error: The specified private key file \"" + privateKeyFileName + "\" is not actually a file");
        }

        if (!privateKeyFile.canRead()) {
            throw new MyConfigurationException("Error: The specified private key file \"" + privateKeyFileName + "\" is not readable. Check the permissions.");
        }

        return KeyUtil.fromPKCS8PEM(new FileReader(privateKeyFile));
    }

    protected PublicKey checkPublicKey() throws IOException {
        String publicKeyFileName = getCfgValue(ClientXMLTags.PUBLIC_KEY);
        if (trivial(publicKeyFileName)) {
            throw new MyConfigurationException("Error: There is no public key specified.");
        }
        File publicKeyFile = new File(publicKeyFileName);
        if (!publicKeyFile.exists()) {
            throw new MyConfigurationException("Error: The specified public key file \"" + publicKeyFileName + "\" does not exist");
        }
        if (!publicKeyFile.isFile()) {
            throw new MyConfigurationException("Error: The specified public key file \"" + publicKeyFileName + "\" is not actually a file");
        }

        if (!publicKeyFile.canRead()) {
            throw new MyConfigurationException("Error: The specified public key file \"" + publicKeyFileName + "\" is not readable. Check the permissions.");
        }

        return KeyUtil.fromX509PEM(new FileReader(publicKeyFile));
    }


    /**
     * This will return a service provider. Do not call this (or for that matter any other getter)
     * until {@link #load()} has been called.
     *
     * @return
     */
    public OA4MPServiceProvider getServiceProvider() {
        return new OA4MPServiceProvider(load());
    }


    @Override
    protected Provider<DelegationService> getDSP() {
              if (dsp == null) {
                  dsp = new DelegationServiceImplProvider(getInitiateURI(),
                          getAccessTokenURI(),
                          getAssetURI());

              }
              return dsp;
          }



}
