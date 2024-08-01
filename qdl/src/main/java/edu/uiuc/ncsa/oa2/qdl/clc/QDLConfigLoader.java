package edu.uiuc.ncsa.oa2.qdl.clc;

import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.FSAssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.MemoryAssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OIDCDiscoveryTags;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.SSLConfigurationUtil2;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoaderImpl;
import edu.uiuc.ncsa.qdl.exceptions.IndexError;
import edu.uiuc.ncsa.qdl.parsing.IniParserDriver;
import edu.uiuc.ncsa.qdl.variables.Constant;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.LoggerProvider;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import net.sf.json.JSONObject;

import javax.inject.Provider;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.logging.Level;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags.CERT_LIFETIME;
import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags.*;
import static edu.uiuc.ncsa.myproxy.oa4mp.client.loader.AbstractClientLoader.defaultCertLifetime;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/23 at  3:35 PM
 */
public class QDLConfigLoader<T extends OA2ClientEnvironment> extends OA2ClientLoaderImpl<T> implements QDLConfigTags {
    public QDLStem getConfig() {
        return config;
    }

    /**
     * The full configuration passed to this. The {@link #getConfig()} is the resolved configuration.
     *
     * @return
     */
    public QDLStem getFullConfig() {
        return fullConfig;
    }

    public void setFullConfig(QDLStem fullConfig) {
        this.fullConfig = fullConfig;
    }

    QDLStem fullConfig;

    protected void initialize(QDLStem s, String configName) {
        fullConfig = s;
        Object obj = null;
        try {
            obj = s.getByMultiIndex(configName); // because the constructor
        } catch (IndexError indexError) {
            throw new IllegalArgumentException(configName + " is not an entry");
        }
        if (obj == null) { // edge case. No entry for some strange reason.
            throw new IllegalArgumentException(configName + " is not an entry");
        }

        if (!(obj instanceof QDLStem)) {
            throw new IllegalArgumentException(configName + " must be a stem, but was a " + obj.getClass().getSimpleName());
        }
        QDLStem base = (QDLStem) obj; // base is the original stem with all the configurations.
        if (base.containsKey(EXTENDS)) {
            obj = base.getByMultiIndex(EXTENDS); // reuse obj;
            QDLStem ext;
            if (obj instanceof QDLStem) {
                ext = (QDLStem) obj; //ext is the list of extensions
            } else {
                if (obj instanceof String) {
                    ext = new QDLStem();
                    ext.put(0L, obj);
                } else {
                    throw new IllegalArgumentException("The extends list must contain only strings");
                }
            }
            if (!ext.isList()) {
                throw new IllegalArgumentException("The extends object must be a list ");
            }
            QDLStem arg = null;
            // so if ext is the current configuration and extends = [a,b,c,d] this is
            // a~b~c~d~ext
            // so much easier in QDL...
            for (Object x : ext.getQDLList().values()) {
                boolean firstPass = true;
                if (!(x instanceof String)) {
                    throw new IllegalArgumentException("All the elements in the extends list must be names of configuration, i.e., strings.");
                }
                if (s.containsKey((String) x)) {
                    QDLStem y = s.getStem((String) x);
                    if (firstPass) {
                        arg = y;
                        firstPass = false;
                    } else {
                        arg = arg.union(y);
                    }
                }
            }
            if (arg != null) {
                base = arg.union(base); // argument overrides values in arg.
            }
        }
        config = base;
    }

    QDLStem config;

    public QDLConfigLoader(QDLStem stem, String configName) {
        initialize(stem, configName); // sets config
        setConfigName(configName);
    }

    public String getConfigName() {
        return configName;
    }

    public void setConfigName(String configName) {
        this.configName = configName;
    }

    String configName;


    Collection<String> scopes;

    @Override
    public Collection<String> getScopes() {
        if (scopes == null) {
            scopes = new ArrayList<>();
        }
        Object obj = getConfig().get(SCOPES);
        if (obj == null) {
            return scopes;
        }
        if (obj instanceof String) {
            scopes.add((String) obj);
        } else {
            if (!(scopes instanceof QDLStem)) {
                QDLStem ss = (QDLStem) obj;
                for (Object key : ss.keySet()) {
                    Object value = ss.get(key);
                    if (value instanceof String) {
                        scopes.add((String) value);
                    }
                }
            }
        }
        return scopes;
    }

    JSONWebKeys jsonWebKeys = null;

    @Override
    public JSONWebKeys getKeys() {
        if (jsonWebKeys == null) {
            String path = getConfig().getString(JWKS);
            JWKUtil2 jwkUtil2 = new JWKUtil2();
            try {
                jsonWebKeys = jwkUtil2.fromJSON(new File(path));
            } catch (IOException e) {
                throw new IllegalArgumentException("the file '" + path + "' could not be loaded:" + e.getMessage());
            }
        }
        return jsonWebKeys;
    }


    Map<String, List<String>> extendedAttributes = null;

    @Override
    public Map<String, List<String>> getAdditionalParameters() {
        if (extendedAttributes == null) {
            extendedAttributes = new HashMap<>();
            if (getConfig().containsKey(EXTENDED_ATTRIBUTES)) {
                QDLStem eas = getConfig().getStem(EXTENDED_ATTRIBUTES);
                // convert to just strings
                for (Object k : eas.keySet()) {
                    if (!Constant.isString(k)) {
                        continue;
                    }
                    String key = (String) k;
                    Object obj = eas.get(key);
                    if (obj instanceof String) {
                        List<String> ll = new ArrayList<>();
                        ll.add((String) obj);
                        extendedAttributes.put(key, ll);
                    } else {
                        if (obj instanceof QDLStem) {
                            QDLStem ea = (QDLStem) obj;
                            extendedAttributes.put(key, ea.getQDLList().values());
                        }
                    }
                }
            }
        }
        return extendedAttributes;
    }

    /*
      <parameters>
     <parameter key="oa4mp:role">researcher</parameter>
     <parameter key="oa4mp:role">admin</parameter>
     <parameter key="oa4mp:/refresh/lifetime">1000000</parameter>

   </parameters>
     */
    Provider<AssetStore> assetStoreProvider = null;

    @Override
    public Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            if (!getConfig().containsKey(ASSET_STORE)) {
                MemoryAssetStore memoryAssetStore = new MemoryAssetStore(getAssetProvider());
                assetStoreProvider = new StupidAssetStoreProvider<>(memoryAssetStore);
            } else {
                QDLStem a = getConfig().getStem(ASSET_STORE);
                switch (a.getString(ASSET_STORE_TYPE)) {
                    case StorageConfigurationTags.FILE_STORE:
                        assetStoreProvider = setupFSAssetStore(a);
                        break;
                    case StorageConfigurationTags.MEMORY_STORE:
                        MemoryAssetStore memoryAssetStore = new MemoryAssetStore(getAssetProvider());
                        assetStoreProvider = new StupidAssetStoreProvider<>(memoryAssetStore);
                        break;
                }
            }
        }
        return assetStoreProvider;
    }

    protected Provider<AssetStore> setupFSAssetStore(QDLStem conf) {
        boolean removeFailedFiles = false;
        boolean removeEmptyFiles = false;
        if (conf.containsKey(FILE_STORE_REMOVE_EMPTY)) {
            removeEmptyFiles = conf.getBoolean(FILE_STORE_REMOVE_EMPTY);
        }
        if (conf.containsKey(FILE_STORE_REMOVE_FAILED)) {
            removeFailedFiles = conf.getBoolean(FILE_STORE_REMOVE_FAILED);
        }
        if (!conf.containsKey(ASSET_FILE_STORE_PATH)) {
            throw new IllegalArgumentException("Missing math for the asset file store");
        }
        String path = conf.getString(ASSET_FILE_STORE_PATH);
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        String dataPath = path + "/" + StorageConfigurationTags.FS_DATA;
        String indexPath = path + "/" + StorageConfigurationTags.FS_INDEX;
        FSAssetStore store = new FSAssetStore(new File(dataPath), new File(indexPath), assetProvider, assetConverter, removeEmptyFiles, removeFailedFiles);
        return new StupidAssetStoreProvider(store);
    }

    public static class StupidAssetStoreProvider<T extends AssetStore> implements Provider<T> {
        AssetStore assetStore;

        public StupidAssetStoreProvider(AssetStore assetStore) {
            this.assetStore = assetStore;
        }

        @Override
        public T get() {
            return (T) assetStore;
        }
    }

    SSLConfiguration sslConfiguration = null;

    @Override
    public SSLConfiguration getSSLConfiguration() {
        if (sslConfiguration == null) {
            if (getConfig().containsKey(SSL)) {
                QDLStem ssl = getConfig().getStem(SSL);
                if (ssl.containsKey(TRUST_STORE_TAG)) {
                    // set this as the default. The assumption is that if there is a trust store, they
                    // don't want the default, though they can override it in the configuration.
                    ssl.getStem(TRUST_STORE_TAG).put(TRUST_STORE_USE_DEFAULT_TRUST_MANAGER, false);
                }
                renameSSLkeys(ssl);
                sslConfiguration = SSLConfigurationUtil2.fromJSON((JSONObject) ssl.toJSON());
            }
        }
        return sslConfiguration;
    }

    /**
     * This will rename the keys to conform to the serialization in {@link SSLConfigurationUtil2}.
     * It's probably the most reliable way to do this.
     *
     * @param ssl
     * @return
     */
    protected void renameSSLkeys(QDLStem ssl) {
        if (ssl.containsKey(TRUST_STORE_TAG)) {
            QDLStem trustStore = ssl.getStem(TRUST_STORE_TAG);
            QDLStem renameKeys = new QDLStem();
            renameKeys.put(QDLConfigTags.TRUST_STORE_TYPE, SSLConfigurationUtil2.SSL_TRUSTSTORE_TYPE);
            renameKeys.put(QDLConfigTags.TRUST_STORE_PATH, SSLConfigurationUtil2.SSL_TRUSTSTORE_PATH);
            renameKeys.put(QDLConfigTags.TRUST_STORE_CERT_DN, SSLConfigurationUtil2.SSL_TRUSTSTORE_CERTIFICATE_DN);
            renameKeys.put(QDLConfigTags.TRUST_STORE_PASSWORD, SSLConfigurationUtil2.SSL_TRUSTSTORE_PASSWORD);
            renameKeys.put(QDLConfigTags.SSL_USE_JAVA_TRUST_STORE, SSLConfigurationUtil2.SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE);
            renameKeys.put(QDLConfigTags.TRUST_STORE_STRICT_HOSTNAME, SSLConfigurationUtil2.SSL_TRUSTSTORE_IS_STRICT_HOSTNAMES);
            renameKeys.put(QDLConfigTags.TRUST_STORE_USE_DEFAULT_TRUST_MANAGER, SSLConfigurationUtil2.SSL_TRUSTSTORE_USE_DEFAULT_TRUST_MANAGER);
            trustStore.renameKeys(renameKeys, true);
            // now to rename the trust_store
            renameKeys = new QDLStem();
            renameKeys.put(QDLConfigTags.TRUST_STORE_TAG, SSLConfigurationUtil2.SSL_TRUSTSTORE_TAG);
            ssl.renameKeys(renameKeys, true);
        }

    }

    /*
                ssl.setTrustRootType(trustStore.getString(SSL_TRUSTSTORE_TYPE));
               ssl.setTrustRootPassword(trustStore.getString(SSL_TRUSTSTORE_PASSWORD));
               ssl.setTrustRootCertDN(trustStore.getString(SSL_TRUSTSTORE_CERTIFICATE_DN));
               ssl.setTrustRootPath(trustStore.getString(SSL_TRUSTSTORE_PATH));
               ssl.setUseDefaultJavaTrustStore(trustStore.getBoolean(SSL_TRUSTSTORE_USE_JAVA_TRUSTSTORE));
               ssl.setUseDefaultTrustManager(trustStore.getBoolean(SSL_TRUSTSTORE_USE_DEFAULT_TRUST_MANAGER));
               ssl.setStrictHostnames(trustStore.getBoolean(SSL_TRUSTSTORE_IS_STRICT_HOSTNAMES));
     */
    String identifier = null;

    @Override
    public String getId() {
        if (identifier == null) {
            identifier = getConfig().getString(ID);
        }
        return identifier;
    }

    String kid = null;

    @Override
    public String getKID() {
        if (kid == null) {
            kid = getConfig().getString(JWK_ID);
        }
        return kid;
    }

    String secret = null;

    @Override
    public String getSecret() {
        if (secret == null) {
            secret = getConfig().getString(SECRET);
        }
        return secret;
    }

    String serviceURI = null;

    @Override
    public String getServiceURI() {
        if (serviceURI == null) {
            serviceURI = getEndpoint(SERVICE_URL);
            if (serviceURI == null) {
                serviceURI = getWellKnownString(OIDCDiscoveryTags.ISSUER);
                // slightly normalize it so we can just construct other endpoints.
                if (serviceURI.endsWith("/")) {
                    serviceURI = serviceURI.substring(0, serviceURI.length() - 1);
                }
            }
        }
        return serviceURI;
    }

    String skin = null;

    @Override
    public String getSkin() {
        if (skin == null) {
            skin = getConfig().getString(SKIN);
        }
        return skin;
    }

    String wellKnownURI = null;

    @Override
    public String getWellKnownURI() {
        if (wellKnownURI == null) {
            wellKnownURI = getEndpoint(WELL_KNOWN_URL);
            if (wellKnownURI == null) {
                if (getServiceURI() != null) {
                    wellKnownURI = getServiceURI() + "/.well-known/openid-configuration";
                }
            }
        }
        return wellKnownURI;
    }

    URI tokenURI = null;

    @Override
    public URI getAccessTokenURI() {
        if (tokenURI == null) {
            tokenURI = createServiceURI(getEndpoint(TOKEN_URL),
                    OIDCDiscoveryTags.TOKEN_ENDPOINT_DEFAULT,
                    OIDCDiscoveryTags.TOKEN_ENDPOINT);
        }
        return tokenURI;
    }

    URI assetURI = null;

    @Override
    public URI getAssetURI() {
        if (assetURI == null) {
            assetURI = URI.create(getServiceURI() + "/getcert"); // as per spec.
        }
        return assetURI;
    }

    URI authorizeURI = null;

    @Override
    public URI getAuthorizeURI() {
        if (authorizeURI == null) {
            authorizeURI = createServiceURI(getEndpoint(AUTHORIZE_URL),
                    OIDCDiscoveryTags.AUTHORIZATION_ENDPOINT_DEFAULT,
                    OIDCDiscoveryTags.AUTHORIZATION_ENDPOINT);

        }
        return authorizeURI;
    }

    URI callback = null;

    @Override
    public URI getCallback() {
        if (callback == null) {
            String x = getConfig().getString(CALLBACK);
            if (x != null) {
                callback = URI.create(x); // avoids an NPE 
            }
        }
        return callback;
    }

    protected String getEndpoint(String name) {
        if (!getConfig().containsKey(ENDPOINTS)) {
            return null;
        }
        return getConfig().getStem(ENDPOINTS).getString(name);
    }

    URI deviceAuthorizationURI = null;

    @Override
    public URI getDeviceAuthorizationURI() {
        if (deviceAuthorizationURI == null) {
            try {
                deviceAuthorizationURI = createServiceURI(getEndpoint(DEVICE_AUTHORIZATION_URL),
                        OIDCDiscoveryTags.DEVICE_AUTHORIZATION_ENDPOINT_DEFAULT,
                        OIDCDiscoveryTags.DEVICE_AUTHORIZATION_ENDPOINT);
            } catch (Throwable t) {
                // it is entirely possible that this server does not have support for
                // device authorization in which case the call to the well-known endpoint
                // fails. This is benign.
            }
        }
        return deviceAuthorizationURI;
    }

    URI revocationURI = null;

    @Override
    public URI getRFC7009Endpoint() {
        if (revocationURI == null) {
            revocationURI = createServiceURI(getEndpoint(REVOCATION_URL),
                    OIDCDiscoveryTags.REVOCATION_ENDPOINT_DEFAULT,
                    OIDCDiscoveryTags.TOKEN_REVOCATION_ENDPOINT);
        }
        return revocationURI;
    }

    URI userInfoURI = null;

    @Override
    public URI getUIURI() {
        if (userInfoURI == null) {
            userInfoURI = createServiceURI(getEndpoint(USER_INFO_URL),
                    OIDCDiscoveryTags.USER_INFO_ENDPOINT_DEFAULT,
                    OIDCDiscoveryTags.USERINFO_ENDPOINT);
        }
        return userInfoURI;
    }

    Boolean enableAssetCleanup = null;

    @Override
    public boolean isEnableAssetCleanup() {
        if (enableAssetCleanup == null) {
            enableAssetCleanup = getConfig().getBoolean(ENABLE_ASSET_CLEANUP);
            if (enableAssetCleanup == null) {
                enableAssetCleanup = false; // default
            }
        }
        return enableAssetCleanup;
    }

    Boolean isOIDC = null;

    @Override
    public boolean isOIDCEnabled() {
        if (isOIDC == null) {
            isOIDC = getConfig().getBoolean(ENABLE_OIDC);
            if (isOIDC == null) {
                isOIDC = true;  // default
            }
        }
        return isOIDC;
    }

    Long certLifetime = null;

    @Override
    public long getCertLifetime() {
        if (certLifetime == null) {
            certLifetime = getConfig().getLong(CERT_LIFETIME);
            if (certLifetime == null) {
                certLifetime = defaultCertLifetime;
            }
        }
        return certLifetime;
    }

    @Override
    public long getKeypairLifetime() {
        return 0;
    }

    URI issuer = null;

    @Override
    public URI getIssuer() {
        if (issuer == null) {
            issuer = createServiceURI(getEndpoint(ISSUER_URI),
                    OIDCDiscoveryTags.ISSUER,
                    OIDCDiscoveryTags.ISSUER);

        }
        return issuer;
    }

    Long maxAssetLiftime = null;

    @Override

    public long getMaxAssetLifetime() {
        if (maxAssetLiftime == null) {
            maxAssetLiftime = getConfig().getLong(MAX_ASSET_LIFETIME);
            if (maxAssetLiftime == null) {
                maxAssetLiftime = AbstractClientLoader.defaultMaxAssetLifetime;
            }
        }
        return maxAssetLiftime;
    }

    URI introspectionURI = null;

    @Override
    public URI getRFC7662Endpoint() {
        if (introspectionURI == null) {
            introspectionURI = createServiceURI(getEndpoint(INTROSPECTION_URL),
                    OIDCDiscoveryTags.INTROSPECTION_ENDPOINT_DEFAULT,
                    OIDCDiscoveryTags.TOKEN_INTROSPECTION_ENDPOINT);
        }
        return introspectionURI;
    }

    @Override
    public T load() {
        return createInstance(); // loading done elsewhere.
    }

    @Override
    public T createInstance() {
        Provider<Client> clientProvider = new Provider<Client>() {
            @Override
            public Client get() {
                return new Client(BasicIdentifier.newID(getId()));
            }
        };
        return (T) new OA2ClientEnvironment(getLoggerProvider().get(),
                getConstants(),
                getAccessTokenURI(),
                getAuthorizeURI(),
                getCallback(),
                getAssetURI(), //resource server
                getCertLifetime(),
                getId(),
                getSkin(),
                isEnableAssetCleanup(),
                getMaxAssetLifetime(),
                getKeypairLifetime(),
                getAssetProvider(),
                clientProvider, // client provider
                tokenForgeProvider,
                getDSP(),
                getAssetStoreProvider(),
                false,
                null,
                null,
                null,
                getSecret(),
                getKID(),
                getKeys(),
                getScopes(),
                getWellKnownURI(),
                isOIDCEnabled(),
                false,
                false,
                getAdditionalParameters(),
                getDeviceAuthorizationURI(),
                getIssuer(),
                getDebugger()
        );
    }

    HashMap<String, String> constants = null;

    @Override
    public HashMap<String, String> getConstants() {
        if (constants == null) {
            constants = new HashMap<>();
            // OAuth 1.0a callback constants remap. OA4MP used to extend it for OAuth 2.0...
            constants.put(ServiceConstantKeys.CALLBACK_URI_KEY, REDIRECT_URI);
            constants.put(ServiceConstantKeys.TOKEN_KEY, AUTHORIZATION_CODE);
            constants.put(ServiceConstantKeys.FORM_ENCODING_KEY, FORM_ENCODING);
            constants.put(ServiceConstantKeys.CERT_REQUEST_KEY, CERT_REQ);
            constants.put(ServiceConstantKeys.CERT_LIFETIME_KEY, OA2Constants.CERT_LIFETIME);
            constants.put(ServiceConstantKeys.CONSUMER_KEY, OA2Constants.CLIENT_ID);
        }
        return constants;
    }

    LoggerProvider loggerProvider = null;

    public LoggerProvider getLoggerProvider() {
        if (loggerProvider == null) {
            String logFile = null;
            String logName = "oa4mp-clc";
            int fileCount = 2;
            int maxFileSize = 100000;
            boolean disableLog4J = true;
            boolean appendOn = false;
            Level level = Level.WARNING;
            QDLStem cfg = getConfig().getStem(LOGGING_TAG);
            if (cfg != null) {
                if (cfg.containsKey(LOGGING_FILE)) logFile = cfg.getString(LOGGING_FILE);
                if (cfg.containsKey(LOGGING_NAME)) logName = cfg.getString(LOGGING_NAME);
                if (cfg.containsKey(LOGGING_MAX_SIZE)) maxFileSize = cfg.getLong(LOGGING_MAX_SIZE).intValue();
                if (cfg.containsKey(LOGGING_COUNT)) fileCount = cfg.getLong(LOGGING_COUNT).intValue();
                if (cfg.containsKey(LOGGING_DISABLE_LOG4J)) disableLog4J = cfg.getBoolean(LOGGING_DISABLE_LOG4J);
                if (cfg.containsKey(LOGGING_ENABLE_APPEND)) appendOn = cfg.getBoolean(LOGGING_ENABLE_APPEND);
            }
            loggerProvider = new LoggerProvider(logFile,
                    logName,
                    fileCount,
                    maxFileSize,
                    disableLog4J,
                    appendOn,
                    level);

        }
        return loggerProvider;
    }

    MetaDebugUtil debugger = null;

    /*
        /**
     * Checks for and sets up the debugging for this loader. Once this is set up, you may have to tell any environments that
     * use it that debugging is enabled.  Note that this is not used in this module, but in OA4MP proper, but has to b
     * here for visibility later.
     */
    @Override
    public MetaDebugUtil getDebugger() {
        if (debugger == null) {
            debugger = getDebugger(getConfig().getString(DEBUG_LEVEL));
        }
        return debugger;
    }

    public static void main(String[] args) throws Throwable {
        String clientFile = "/home/ncsa/dev/csd/config/auto-test/clients.ini";
        String cfgName = "commandline2";
        IniParserDriver iniParserDriver = new IniParserDriver();
        FileReader fileReader = new FileReader(clientFile);
        QDLStem out = iniParserDriver.parse(fileReader, true);
        QDLConfigLoader<? extends OA2ClientEnvironment> loader = new QDLConfigLoader<>(out, cfgName);
        OA2ClientEnvironment ce = loader.load();
    }
}
