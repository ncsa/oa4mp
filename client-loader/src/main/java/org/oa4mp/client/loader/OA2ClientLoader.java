package org.oa4mp.client.loader;

import org.oa4mp.delegation.server.OA2ConfigurationLoaderUtils;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.OA2TokenForge;
import org.oa4mp.delegation.server.OIDCDiscoveryTags;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.client.api.ClientEnvironment;
import org.oa4mp.client.api.ClientXMLTags;
import org.oa4mp.client.api.OA4MPServiceProvider;
import org.oa4mp.client.api.loader.AbstractClientLoader;
import org.oa4mp.client.api.storage.*;
import org.oa4mp.delegation.DelegationService;
import org.oa4mp.delegation.common.OA4MPVersion;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.server.client.*;

import javax.inject.Provider;
import java.io.File;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.oa4mp.client.api.ClientEnvironment.CALLBACK_URI_KEY;
import static org.oa4mp.client.api.ClientXMLTags.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:34 PM
 */
public class OA2ClientLoader<T extends ClientEnvironment> extends AbstractClientLoader<T> {

    public OA2ClientLoader(ConfigurationNode node) {
        super(node);
    }

    /**
     * Constructor to inject a logger. 
     * @param node
     * @param logger
     */
    public OA2ClientLoader(ConfigurationNode node, MyLoggingFacade logger ) {
        super(node, logger);
    }

    @Override
    public String getVersionString() {
        return "OA4MP Client OAuth 2 configuration loader, version " + OA4MPVersion.VERSION_NUMBER;
    }

    public OA4MPServiceProvider getServiceProvider() {
        return new OA2MPServiceProvider(load());
    }

    protected Collection<String> scopes = null;

    public Collection<String> getScopes() {
        if (scopes == null) {
            scopes = OA2ConfigurationLoaderUtils.getScopes(cn);
        }
        return scopes;
    }

    Map<String, List<String>> additionalParameters = null;

    public Map<String, List<String>> getAdditionalParameters() {
        if (additionalParameters == null) {
            additionalParameters = OA2ConfigurationLoaderUtils.getAdditionalParameters(cn);
        }
        return additionalParameters;
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
            if(StringUtils.isTrivial(myLogger.getClassName())) {
                myLogger.setClassName("oa4mp-client"); // so it has a default name.
            }
            return (T) new OA2ClientEnvironment(
                    myLogger, constants,
                    getAccessTokenURI(),
                    getAuthorizeURI(),
                    getCallback(),
                    getAssetURI(),
                    getCertLifetime(),
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
                    getKID(),
                    getKeys(),
                    getScopes(),
                    getWellKnownURI(),
                    isOIDCEnabled(),
                    isShowIDToken(),
                    isUseBasicAuth(),
                    getAdditionalParameters(),
                    getDeviceAuthorizationURI(),
                    getIssuer(),
                    getDebugger()
            );
        } catch (Throwable e) {
            throw new GeneralException("Unable to create client environment", e);
        }
    }

    AssetProvider assetProvider = null;

    @Override
    public AssetProvider getAssetProvider() {
        if (assetProvider == null) {
            assetProvider = new OA2AssetProvider();
        }
        return assetProvider;
    }



    Boolean showIDToken = null;

    /**
     * An option for the (demo) client that specifies that the user should be shown the ID token at some point.
     * Default is <code>false</code>.<br/><br/>
     * This is really old and was used in OAuth 1.0a demos. It would stop the flow and let the user inspect
     * the id token, then allow the flow to continue. It should probably get tracked down and removed
     * The current default client shows the ID token every time, so this really is not needed.
     *
     * @return
     * @deprecated
     */
    public boolean isShowIDToken() {
        if (showIDToken == null) {
/*            try {
                showIDToken = Boolean.parseBoolean(getCfgValue(ClientXMLTags.SHOW_ID_TOKEN));
            } catch (Throwable t) {
                showIDToken = Boolean.FALSE;
            }*/
            // from https://github.com/rcauth-eu/OA4MP/commit/c7c49a750b3138e542353a1acb01d4e4eb3883cf
            String showIDTokenValue = getCfgValue(ClientXMLTags.SHOW_ID_TOKEN);
            if (showIDTokenValue == null) {
                // NOTE: showIDToken is used only by OA2ReadyServlet via isShowIDToken() and used for debug purposes only.
                showIDToken = Boolean.FALSE; // default
                info("No value for " + ClientXMLTags.SHOW_ID_TOKEN + " is configured, using default \"" + showIDToken + "\"");
            } else {
                // Note: parseBoolean() only knows true, anything else becomes false.
                showIDToken = Boolean.parseBoolean(showIDTokenValue);
                debug("Value for " + ClientXMLTags.SHOW_ID_TOKEN + " parsed as " + showIDToken);
                ServletDebugUtil.trace(this, "setting " + ClientXMLTags.SHOW_ID_TOKEN + " to " + showIDToken);
            }
        }
        return showIDToken;
    }

    Boolean oidcEnabled = null;

    public boolean isOIDCEnabled() {
        if (oidcEnabled == null) {
            oidcEnabled = Boolean.TRUE; // default
            String content = getCfgValue(ClientXMLTags.OIDC_ENABLED);
            if (content == null || content.isEmpty()) {
                // use default
                return oidcEnabled;
            }
            try {
                oidcEnabled = Boolean.parseBoolean(content);
            } catch (Throwable t) {
                // do nothing. Rock on
                warn("Unable to parse " + ClientXMLTags.OIDC_ENABLED + " element content of \"" + content + "\". Using default of true.");
            }
        }
        return oidcEnabled;
    }

    @Override
    public Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            OA2AssetSerializationKeys keys = new OA2AssetSerializationKeys();
            OA2AssetConverter assetConverter = new OA2AssetConverter(keys, getAssetProvider());
            assetStoreProvider = masp;
            masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE, getPgConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new OA2SQLAssetStoreProvider(cn, ClientXMLTags.DERBY_STORE, getDerbyConnectionPoolProvider(),
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

    public String getSecret() {
        return getCfgValue(ClientXMLTags.SECRET_KEY);
    }

    public String getKID() {
        return getCfgValue(JWK_KEY_ID);
    }

    /**
     * Check if there is a JWK specified as a file
     *
     * @return
     */
    protected JSONWebKeys getKeysFromFile() {
        String fname = getCfgValue(JWKS_FILE);
        if (StringUtils.isTrivial(fname)) {
            return null;
        }
        try {
            return getJwkUtil().fromJSON(new File(fname));
        } catch (Throwable t) {
            if (debugger.isEnabled()) {
                t.printStackTrace();
            }
        }
        return null;
    }

    /**
     * Check if there is JWK specified directly (as a string of JSON) in the configuration.
     *
     * @return
     */
    protected JSONWebKeys getKeysFromString() {
        String raw = getCfgValue(JWKS);
        if (StringUtils.isTrivial(raw)) {
            return null;
        }
        try {
            return getJwkUtil().fromJSON(raw);
        } catch (Throwable t) {
            if (debugger.isEnabled()) {
                t.printStackTrace();
            }
        }
        return null;

    }

    public JWKUtil2 getJwkUtil() {
        if(jwkUtil == null){
            jwkUtil = new JWKUtil2();
        }
        return jwkUtil;
    }

    public void setJwkUtil(JWKUtil2 jwkUtil) {
        this.jwkUtil = jwkUtil;
    }

    JWKUtil2 jwkUtil;
    JSONWebKeys jwks = null;

    public JSONWebKeys getKeys() {
        if (jwks == null) {
            jwks = getKeysFromFile();
            if (jwks == null) {
                jwks = getKeysFromString();
            }else{
                JSONWebKeys jwks2 = getKeysFromString(); // check file for integrity
                if(jwks2!=null){
                    throw new GeneralException("two JWKs specified in the configuration. Only one is allowed");
                }
            }
        }
        return jwks;
    }

    protected boolean hasJWKS() {
        return getKeys() != null;
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
                return new Client(BasicIdentifier.newID(getId()));
            }
        };

        // sets constants specific to this protocol.
        HashMap<String, String> constants = new HashMap<String, String>();
        constants.put(CALLBACK_URI_KEY, OA2Constants.REDIRECT_URI);
        constants.put(ClientEnvironment.FORM_ENCODING, OA2Constants.FORM_ENCODING);
        // https://github.com/rcauth-eu/OA4MP/commit/a94a86fbe654a80a552ddb0255cbadb5d8e8fb72 remove spurious constants.put
        //constants.put(ClientEnvironment.TOKEN, OA2Constants.ACCESS_TOKEN);
        constants.put(ClientEnvironment.TOKEN, OA2Constants.AUTHORIZATION_CODE);
        // no verifier in this protocol.
        T t = createInstance(tokenForgeProvider, clientProvider, constants);
        t.setDebugOn(DebugUtil.isEnabled());
        return t;
    }


    Boolean useBasicAuth = null;

    /**
     * For calls the client makes to the service, use HTTP Basic Authorization rather than passing in the
     * credentials as parameters. Both should be supported, but some other services might only allow for this.
     * This feature is (probably) unused and should be removed at some point.
     *
     * @return
     * @deprecated
     */
    public Boolean isUseBasicAuth() {
        if (useBasicAuth == null) {
            try {
                useBasicAuth = Boolean.parseBoolean(getCfgValue(ClientXMLTags.USE_HTTP_BASIC_AUTHORIZATIION));
            } catch (Throwable t) {
                useBasicAuth = Boolean.FALSE;
            }
        }
        return useBasicAuth;
    }

    public void setUseBasicAuth(Boolean useBasicAuth) {
        this.useBasicAuth = useBasicAuth;
    }

    @Override
    protected Provider<DelegationService> getDSP() {
        if (dsp == null) {
            dsp = new Provider<DelegationService>() {
                @Override
                public DelegationService get() {
                    //return new DS2(new AGServer2(createServiceClient(getAuthzURI())), // as per spec, request for AG comes through authz endpoint.
                    return new DS2(new AGServer2(createServiceClient(getAuthorizeURI())), // as per spec, request for AG comes through authz endpoint.
                            new ATServer2(createServiceClient(getAccessTokenURI()),
                                    getIssuer(),
                                    getWellKnownURI(),
                                    isOIDCEnabled(),
                                    getMaxAssetLifetime(),
                                    isUseBasicAuth()),
                            new PAServer2(createServiceClient(getAssetURI())),
                            new UIServer2(createServiceClient(getUIURI())),
                            new RTServer2(createServiceClient(getAccessTokenURI()), getIssuer(), getWellKnownURI(), isOIDCEnabled()), // as per spec, refresh token server is at same endpoint as access token server.
                            new RFC7009Server2(createServiceClient(getRFC7009Endpoint()), getIssuer(), getWellKnownURI(), isOIDCEnabled()),
                            new RFC7662Server2(createServiceClient(getRFC7662Endpoint()),getIssuer(), getWellKnownURI(), isOIDCEnabled()),
                            new RFC7523Server(createServiceClient(getAccessTokenURI()), getIssuer(), getWellKnownURI(), isOIDCEnabled()),
                            new RFC8623Server(createServiceClient(getDeviceAuthorizationURI()), getIssuer(), getWellKnownURI(), isOIDCEnabled())
                    );
                }
            };
        }
        return dsp;
    }

/*    URI getTagURI(String tag, String discoveryTag){
        String x = getCfgValue(tag);
        if(StringUtils.isTrivial(x)){
            return URI.create(getWellKnownValue(discoveryTag));
        }
        return createServiceURIOLD(x, getBaseURI(), USER_INFO_ENDPOINT);

    }*/
    public URI getUIURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.USER_INFO_URI),
                OIDCDiscoveryTags.USER_INFO_ENDPOINT_DEFAULT,
                OIDCDiscoveryTags.USERINFO_ENDPOINT);
        //return createServiceURIOLD(getCfgValue(ClientXMLTags.USER_INFO_URI), getCfgValue(ClientXMLTags.BASE_URI), USER_INFO_ENDPOINT);
    }

    public URI getDeviceAuthorizationURI() {
        return createServiceURI(getCfgValue(DEVICE_AUTHORIZATION_URI),
                OIDCDiscoveryTags.DEVICE_AUTHORIZATION_ENDPOINT_DEFAULT,
                OIDCDiscoveryTags.DEVICE_AUTHORIZATION_ENDPOINT);
//        return createServiceURIOLD(getCfgValue(DEVICE_AUTHORIZATION_URI), getCfgValue(ClientXMLTags.BASE_URI), DEVICE_AUTHORIZATION_ENDPOINT);
    }

    public URI getRFC7009Endpoint() {
        return createServiceURI(getCfgValue(REVOCATION_URI),
                OIDCDiscoveryTags.REVOCATION_ENDPOINT_DEFAULT,
                OIDCDiscoveryTags.TOKEN_REVOCATION_ENDPOINT);
//        return createServiceURIOLD(getCfgValue(REVOCATION_URI), getBaseURI(), REVOCATION_ENDPOINT);
    }

    public URI getRFC7662Endpoint() {
        return createServiceURI(getCfgValue(INTROSPECTION_URI),
              OIDCDiscoveryTags.INTROSPECTION_ENDPOINT_DEFAULT,
              OIDCDiscoveryTags.TOKEN_INTROSPECTION_ENDPOINT);
        
        //return createServiceURIOLD(getCfgValue(INTROSPECTION_URI), getBaseURI(), INTROSPECTION_ENDPOINT);
    }

/*    protected URI getAuthzURI() {
        return createServiceURIOLD(getCfgValue(ClientXMLTags.AUTHORIZE_TOKEN_URI), getCfgValue(ClientXMLTags.BASE_URI), AUTHORIZE_ENDPOINT);
    }*/


    @Override
    public HashMap<String, String> getConstants() {
        throw new NotImplementedException("Error: This method is not implemented.");
    }
}
