package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPServiceProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.client.DelegationService;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ConfigurationLoaderUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.client.*;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment.CALLBACK_URI_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:34 PM
 */
public class OA2ClientLoader<T extends ClientEnvironment> extends AbstractClientLoader<T> {

    public OA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    @Override
    public String getVersionString() {
        return "OA4MP Client OAuth 2 configuration loader, version " + VERSION_NUMBER;
    }

    public OA4MPServiceProvider getServiceProvider() {
        return new OA2MPServiceProvider(load());
    }

    protected Collection<String> scopes = null;
    public Collection<String> getScopes() throws IllegalAccessException, InstantiationException, ClassNotFoundException {
        if(scopes == null){
            scopes =  OA2ConfigurationLoaderUtils.getScopes(cn);
        }
        return scopes;
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
        try {
            return (T) new OA2ClientEnvironment(
                    myLogger, constants,
                    getAccessTokenURI(),
                    getAuthorizeURI(),
                    getCallback(),
                    getInitiateURI(),
                    getAssetURI(),
                    checkCertLifetime(),
                    getId(),
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
                    getSuccessPagePath(),
                    getSecret(),
                    getScopes(),
                    getWellKnownURI()
            );
        } catch (Throwable e) {
            throw new GeneralException("Unable to create client environment", e);
        }
    }

    AssetProvider assetProvider = null;
    @Override
    public AssetProvider getAssetProvider() {
        if(assetProvider == null){
            assetProvider = new OA2AssetProvider();
        }
        return assetProvider;
    }

    String wellKnownURI = null;
    public String getWellKnownURI(){
        if(wellKnownURI == null){
             wellKnownURI = getCfgValue("wellKnownUri");
        }
        return wellKnownURI;

    }
    @Override
    protected Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            OA2AssetSerializationKeys keys = new OA2AssetSerializationKeys();
            OA2AssetConverter assetConverter = new OA2AssetConverter(keys, getAssetProvider());
            assetStoreProvider = masp;
            masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE, getPgConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MYSQL_STORE, getMySQLConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.MARIADB_STORE, getMariaDBConnectionPoolProvider(),
                                getAssetProvider(), assetConverter));
            // and a memory store, So only if one is requested it is available.
            masp.addListener(new TypedProvider<MemoryAssetStore>(cn, ClientXMLTags.MEMORY_STORE, ClientXMLTags.ASSET_STORE) {
                @Override
                public Object componentFound(CfgEvent configurationEvent) {
                    if (checkEvent(configurationEvent)) {
                        return get();
                    }
                    return null;
                }

                @Override
                public MemoryAssetStore get() {
                    return new MemoryAssetStore(getAssetProvider());
                }
            });
        }
        return assetStoreProvider;
    }

    protected String getErrorPagePath() {
        return getCfgValue(ClientXMLTags.ERROR_PAGE_PATH);
    }

    protected String getSecret() {
        return getCfgValue(ClientXMLTags.SECRET_KEY);
    }


    protected String getSuccessPagePath() {
        return getCfgValue(ClientXMLTags.SUCCESS_PAGE_PATH);
    }

    protected String getRedirectPagePath() {
        return getCfgValue(ClientXMLTags.REDIRECT_PAGE_PATH);
    }


    protected boolean isShowRedirectPage() {
        String temp = getCfgValue(ClientXMLTags.SHOW_REDIRECT_PAGE);
        if (temp == null || temp.length() == 0) return false;
        return Boolean.parseBoolean(getCfgValue(ClientXMLTags.SHOW_REDIRECT_PAGE));

    }

    @Override
    public T createInstance() {

        Provider<TokenForge> tokenForgeProvider = new Provider<TokenForge>() {
            @Override
            public TokenForge get() {
                return new OA2TokenForge(getId());
            }
        };

        Provider<Client> clientProvider = new Provider<Client>() {
            @Override
            public Client get() {
                return new OA2Client(BasicIdentifier.newID(getId()));
            }
        };

        // sets constants specific to this protocol.
        HashMap<String, String> constants = new HashMap<String, String>();
        constants.put(CALLBACK_URI_KEY, OA2Constants.REDIRECT_URI);
        constants.put(ClientEnvironment.FORM_ENCODING, OA2Constants.FORM_ENCODING);
        constants.put(ClientEnvironment.TOKEN, OA2Constants.ACCESS_TOKEN);
        constants.put(ClientEnvironment.TOKEN, OA2Constants.AUTHORIZATION_CODE);
        // no verifier in this protocol.
        return createInstance(tokenForgeProvider, clientProvider, constants);
    }

    @Override
    protected Provider<DelegationService> getDSP() {
        if (dsp == null) {
            dsp = new Provider<DelegationService>() {
                @Override
                public DelegationService get() {
                    return new DS2(new AGServer2(createServiceClient(getAuthzURI())), // as per spec, request for AG comes through authz endpoint.
                            new ATServer2(createServiceClient(getAccessTokenURI()), getWellKnownURI()),
                            new PAServer2(createServiceClient(getAssetURI())),
                            new UIServer2(createServiceClient(getUIURI())),
                            new RTServer2(createServiceClient(getAccessTokenURI())) // as per spec, refresh token server is at same endpoint as access token server.
                    );
                }
            };
        }
        return dsp;
    }

    protected URI getUIURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.USER_INFO_URI), getCfgValue(ClientXMLTags.BASE_URI), USER_INFO_ENDPOINT);
    }

    protected URI getAuthzURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.AUTHORIZE_TOKEN_URI), getCfgValue(ClientXMLTags.BASE_URI), AUTHORIZE_ENDPOINT);
    }
}
