package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.client.AbstractClientEnvironment;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

import javax.inject.Provider;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

import static edu.uiuc.ncsa.security.util.pkcs.KeyUtil.toPKCS8PEM;

/**
 * Environment under which a client instance runs. Generally this is called by the loader and populated
 * from the configuration file.
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  3:27:56 PM
 */
public class ClientEnvironment extends AbstractClientEnvironment {
    public static final String CALLBACK_URI_KEY = "oa4mp:callback_uri";
    public static final String TOKEN = "oa4mp:token";
    public static final String FORM_ENCODING = "oa4mp:form_encoding"; //usually UTF-8...
    public static final String VERIFIER = "oa4mp:verifier"; //usually UTF-8...

    /**
     * Used mostly for testing.
     * @param accessTokenUri
     * @param authorizationUri
     * @param callback
     * @param certLifetime
     * @param clientId
     * @param delegationService
     * @param initializeUri
     * @param privateKey
     * @param publicKey
     * @param resourceServerUri
     * @param tokenForge
     * @param assetStore
     */

    public ClientEnvironment(URI accessTokenUri,
                             URI authorizationUri,
                             URI callback,
                             long certLifetime,
                             String clientId,
                             DelegationService delegationService,
                             URI initializeUri,
                             PrivateKey privateKey,
                             PublicKey publicKey,
                             URI resourceServerUri,
                             TokenForge tokenForge,
                             AssetStore assetStore,
                             boolean showRedirectPage,
                             String errorPagePath,
                             String redirectPagePath,
                             String successPagePath
    ) {
        this.accessTokenUri = accessTokenUri;
        this.authorizationUri = authorizationUri;
        this.callback = callback;
        this.certLifetime = certLifetime;
        this.clientId = clientId;
        this.delegationService = delegationService;
        this.initializeUri = initializeUri;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.resourceServerUri = resourceServerUri;
        this.tokenForge = tokenForge;
        this.assetStore = assetStore;
        this.skin = null;
        this.showRedirectPage =showRedirectPage;
        if(errorPagePath != null){this.errorPagePath = errorPagePath;}
        if(successPagePath != null){this.successPagePath = successPagePath;}
        if(redirectPagePath != null){this.redirectPagePath = redirectPagePath;}
    }


    AssetStore assetStore;

    /**
     * Returns <code>true</code> if a store has been configured for this environment and
     * <code>false</code> otherwise. Check this before using the store.
     * @return
     */
    public boolean hasAssetStore() {
        return getAssetStore() != null;
    }

    /**
     * Main constructor called by the loader.
     * @param logger
     * @param constants
     * @param accessTokenUri
     * @param authorizationUri
     * @param callback
     * @param initializeUri
     * @param resourceServerUri
     * @param certLifetime
     * @param clientId
     * @param privateKey
     * @param publicKey
     * @param clientProvider
     * @param tokenForgeProvider
     * @param delegationServiceProvider
     * @param assetStoreProvider
     */
    public ClientEnvironment(
            MyLoggingFacade logger,
            Map<String, String> constants,
            URI accessTokenUri,
            URI authorizationUri,
            URI callback,
            URI initializeUri,
            URI resourceServerUri,
            long certLifetime,
            String clientId,
            PrivateKey privateKey,
            PublicKey publicKey,
            String skin,
            boolean enableAssetCleanup,
            long maxAssetLifetime,
            long keypairLifetime,
            AssetProvider assetProvider,
            Provider<Client> clientProvider,
            Provider<TokenForge> tokenForgeProvider,
            Provider<DelegationService> delegationServiceProvider,
            Provider<AssetStore> assetStoreProvider,
            boolean showRedirectPage,
            String errorPagePath,
            String redirectPagePath,
            String successPagePath
    ) {

        super(logger, constants);
        this.accessTokenUri = accessTokenUri;
        this.authorizationUri = authorizationUri;
        this.callback = callback;
        this.initializeUri = initializeUri;
        this.resourceServerUri = resourceServerUri;
        this.certLifetime = certLifetime;
        this.clientId = clientId;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.cp = clientProvider;
        this.dsp = delegationServiceProvider;
        this.tfp = tokenForgeProvider;
        this.assetStoreProvider = assetStoreProvider;
        this.assetProvider = assetProvider;
        this.skin = skin;
        this.enableAssetCleanup = enableAssetCleanup;
        this.maxAssetLifetime = maxAssetLifetime;
        this.keypairLifetime = keypairLifetime;
        this.showRedirectPage = showRedirectPage;
        if(errorPagePath != null){this.errorPagePath = errorPagePath;}
        if(successPagePath != null){this.successPagePath = successPagePath;}
        if(redirectPagePath != null){this.redirectPagePath = redirectPagePath;}

    }


    protected URI accessTokenUri;
    protected URI authorizationUri;
    protected URI initializeUri;
    protected URI resourceServerUri;
    Provider<AssetStore> assetStoreProvider;

    /**
     * Returns the configured {@link AssetStore} for this environment or <code>null</code> if
     * there is none.
     * @return
     * @see #hasAssetStore()
     */
    public AssetStore getAssetStore() {
        if (assetStore == null) {
            if (assetStoreProvider != null) {
                assetStore = assetStoreProvider.get();
            }
        }
        return assetStore;
    }

    public AssetProvider getAssetProvider() {
        return assetProvider;
    }

    public void setAssetProvider(AssetProvider assetProvider) {
        this.assetProvider = assetProvider;
    }

    AssetProvider assetProvider;
    /**
     * The endpoint for this client for retrieving an access token.
     * @return
     */
    public URI getAccessTokenUri() {
        return accessTokenUri;
    }

    /**
     * The endpoint for this client allowing authorization of the user.
     * @return
     */
    public URI getAuthorizationUri() {
        return authorizationUri;
    }

    /**
     * The endpoint for this client that starts delegation.
     * @return
     */
    public URI getInitializeUri() {
        return initializeUri;
    }

    /**
     * The endpoint for this client for getting the resource (i.e., certificate chain).
     * @return
     */
    public URI getResourceServerUri() {
        return resourceServerUri;
    }



    TokenForge tokenForge;

    /**
     * Internal call to the forge (a type of factory) that processing tokens returned from the
     * server. This is public merely because of java package limitations and generally is of no
     * interest to developers.
     * @return
     */

    public TokenForge getTokenForge() {
        if (tokenForge == null) {
            tokenForge = tfp.get();
        }
        return tokenForge;
    }

    DelegationService delegationService;

    Provider<DelegationService> dsp;


    /**
     * The {@link OA4MPService}, fully configured and operational.
     * @return
     */
    public DelegationService getDelegationService() {
        if (delegationService == null) {
            delegationService = dsp.get();
        }
        return delegationService;
    }


    PrivateKey privateKey;
    PublicKey publicKey;
    String clientId;
    protected URI callback;

    /**
     * The callback for this environment.<br>
     *  <B>NOTE</B> Generally this is specified in the configuration file and
     *  is the same for every request. However, if a client wishes to have a different callback uri per request,
     *  simply reset this before each request as needed using the {@link #setCallback(java.net.URI)}.
     * @return
     */
    public URI getCallback() {
        return callback;
    }

    public void setCallback(URI callback) {
        this.callback = callback;
    }

    /**
     * The identifier for this client to the given server. This is read from the configuration file and
     * should not be changed.
     * @return
     */
    public String getClientId() {
        return clientId;
    }


    /**
     * The private key for this client. This is specified in the configuration file and is used for
     * signing request, not for certificate requests. it is paired with the {@link #getPublicKey()}
     * @return
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }


    /**
     * The generated public key for this client. This was supplied to the server at registration time. It
     * is normally read from a configuration file.
     * @return
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Internal call to convert the private key.
     * @return
     */

    protected String getPrivKeyString() {
        if (privKeyString == null) {
            try {
                privKeyString = toPKCS8PEM(getPrivateKey());
            } catch (Exception e) {
                throw new GeneralException("Error: could not convert private key to a PKCS 8 PEM", e);
            }
        }
        return privKeyString;
    }

    protected String privKeyString;

    protected Provider<Client> cp;
    protected Provider<TokenForge> tfp;

    /**
     * A {@link Client} object representing the instance of this service.
     * @return
     */
    public Client getClient() {
        if (client == null) {
            client = cp.get();
            client.setIdentifier(new BasicIdentifier(getClientId()));
            client.setSecret(getPrivKeyString());
        }
        return client;
    }

    /**
     * The certificate lifetime request. This is usually the same for every request and is specified in the
     * client configuration file. It may be reset per request using the {@link #setCertLifetime(long)}
     * @return
     */
    public long getCertLifetime() {
        return certLifetime;
    }

    public void setCertLifetime(long newCertLifetime){
        certLifetime = newCertLifetime;
    }

    long certLifetime = 0L;
    protected Client client;

    protected String skin;

    /**
     * Optional skinning option. If the server supports a customized look and feel for a client, that will
     * be used when this parameter is supplied.
     * @return
     */
    public String getSkin(){
        return skin;
    }

    public long getKeypairLifetime() {
        return keypairLifetime;
    }


    long keypairLifetime = -1L;

    long maxAssetLifetime = -1L;

    public long getMaxAssetLifetime() {
        return maxAssetLifetime;
    }

    boolean enableAssetCleanup;

    public boolean isEnableAssetCleanup() {
        return enableAssetCleanup;
    }

    boolean showRedirectPage = false;
    public boolean isShowRedirectPage() {
        return showRedirectPage;
    }

    public String getErrorPagePath() {
        return errorPagePath;
    }

    public void setErrorPagePath(String errorPagePath) {
        this.errorPagePath = errorPagePath;
    }

    public String getSuccessPagePath() {
        return successPagePath;
    }

    public void setSuccessPagePath(String successPagePath) {
        this.successPagePath = successPagePath;
    }

    public String getRedirectPagePath() {
        return redirectPagePath;
    }

    public void setRedirectPagePath(String redirectPagePath) {
        this.redirectPagePath = redirectPagePath;
    }

    protected String errorPagePath="/pages/client-error.jsp";
    protected String successPagePath="/pages/client-success.jsp";
    protected String redirectPagePath="/pages/client-show-redirect.jsp";
}
