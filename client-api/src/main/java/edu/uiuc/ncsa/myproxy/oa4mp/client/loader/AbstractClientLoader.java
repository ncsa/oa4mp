package edu.uiuc.ncsa.myproxy.oa4mp.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientLoaderInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.oa4mp.delegation.client.DelegationService;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.DBConfigLoader;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OIDCDiscoveryTags;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags.*;

/**
 * Top-level class for client loader that creates asset store and controls which classes are instantiated for the client.
 * <p>Created by Jeff Gaynor<br>
 * on 11/25/13 at  1:12 PM
 */
public abstract class AbstractClientLoader<T extends ClientEnvironment> extends DBConfigLoader<T> implements ClientLoaderInterface<T> {
    public static final String ASSET_ENDPOINT = "getcert";

    // FIX for OAUTH-137. Set default cert lifetime to be 12 hours, not 10 days.
    public static final long defaultCertLifetime = 43200L; // default is 12 hours, in seconds.

    public static final long defaultMaxAssetLifetime = 30 * 24 * 3600000L; // set it for a month in milliseconds

    protected AbstractClientLoader(ConfigurationNode node) {
        super(node);
    }

    protected AbstractClientLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    protected Provider<AssetStore> assetStoreProvider;


    public abstract AssetProvider getAssetProvider();

    public Provider<AssetStore> getAssetStoreProvider() {
        if (assetStoreProvider == null) {
            MultiAssetStoreProvider masp = new MultiAssetStoreProvider(cn, isDefaultStoreDisabled(), loggerProvider.get());
            //final AssetProvider assetProvider = new AssetProvider();
            AssetConverter assetConverter = new AssetConverter(new AssetSerializationKeys(), getAssetProvider());
            assetStoreProvider = masp;
            masp.addListener(new FSAssetStoreProvider(cn, getAssetProvider(), assetConverter));
            masp.addListener(new SQLAssetStoreProvider(cn, ClientXMLTags.POSTGRESQL_STORE, getPgConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new SQLAssetStoreProvider(cn, ClientXMLTags.DERBY_STORE, getDerbyConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new SQLAssetStoreProvider(cn, ClientXMLTags.MYSQL_STORE, getMySQLConnectionPoolProvider(),
                    getAssetProvider(), assetConverter));
            masp.addListener(new SQLAssetStoreProvider(cn, ClientXMLTags.MARIADB_STORE, getMariaDBConnectionPoolProvider(),
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

    protected Provider<DelegationService> dsp;

    abstract protected Provider<DelegationService> getDSP();

    /**
     * Checks the uri. The componentName is simply used for a more readable error messages
     * if the uri is trivial or there is some syntax error with it.
     *
     * @param uri
     * @param componentName
     * @return
     */
    protected URI checkURI(String uri, String componentName) {
        if (trivial(uri)) {
            throw new MyConfigurationException("Error: There is no " + componentName + " URI specified.");
        }
        try {
            // set it this way rather than with URI.create so we get a recognizable exception to hand back.
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new MyConfigurationException("Error: The specified " + componentName + " is not a valid URI", e);
        }

    }

    /**
     * This takes a key and returns the value of the node associated with that key. Returns null
     * if no such value.
     *
     * @param key
     * @return
     */
    protected String getCfgValue(String key) {
        return Configurations.getNodeValue(cn, key);
    }


    public String getSkin() {
        return getCfgValue(SKIN);
    }

    public long getKeypairLifetime() {
        String x = getCfgValue(KEYPAIR_LIFETIME);
        long y = 0L; // OAUTH-167: set it to 0 (no key caching) by default
        if (x == null || x.length() == 0) return y;
        try {
            // The value in the file is assumed to be in seconds.
            y = Long.parseLong(x) * 1000L;
        } catch (NumberFormatException nfx) {
            // use default...
        }
        return y;
    }

    public long getMaxAssetLifetime() {
        String x = getCfgValue(MAX_ASSET_LIFETIME);
        long y = defaultMaxAssetLifetime; // set it for a month in milliseconds
        if (x == null || x.length() == 0) return y;
        try {
            // The value in the file is assumed to be in seconds.
            y = Long.parseLong(x) * 1000L;
        } catch (NumberFormatException nfx) {
            // use default...
        }
        return y;
    }

    public boolean isEnableAssetCleanup() {
        boolean doIt = false;
        try {
            doIt = Boolean.parseBoolean(getCfgValue(ENABLE_ASSET_CLEANUP));
        } catch (Throwable t) {
            // do nothing....
        }
        return doIt;
    }


    /**
     * Checks if there is a found uri in the configuration, i.e., an override
     * to whatever the standard is. If so, check that and use it,
     * if not, try and construct the service endpoint from the base uri and
     * the default serviceEndpoint.
     *
     * @param foundURI
     * @param baseUri
     * @param serviceEndpoint
     * @return
     */
    protected URI createServiceURIOLD(String foundURI, String baseUri, String serviceEndpoint) {
        if (!trivial(foundURI)) {
            return checkURI(foundURI, serviceEndpoint);
        }
        if (trivial(baseUri)) {
            throw new MyConfigurationException("Error: No base uri for " + serviceEndpoint + " found");
        }
        return checkURI(baseUri + (baseUri.endsWith("/") ? "" : "/") + serviceEndpoint, serviceEndpoint);
    }

    /**
     * Creates the service URI. This takes
     * <ol>
     *     <li>The tag in the configuration file</li>
     *     <li>The default endpoint name (used to construct error messages)</li>
     *     <li>The key in the well-known page to get the value from.</li>
     * </ol>
     * @param foundURI
     * @param endpoint
     * @param wellKnownEntry
     * @return
     */
    protected URI createServiceURI(String foundURI, String endpoint, String wellKnownEntry) {
        if (!trivial(foundURI)) {
            return checkURI(foundURI, wellKnownEntry);
        }
        if (getWellKnownURI() != null) {
            return checkURI(getWellKnownString(wellKnownEntry), wellKnownEntry);
        }
        // failing that, try to construct it
        if (trivial(getServiceURI())) {
            return null;
        }
        return checkURI(getServiceURI() + "/" + endpoint, endpoint);
    }

    public long getCertLifetime() {
        String certLifetimeString = getCfgValue(ClientXMLTags.CERT_LIFETIME);
        if (!trivial(certLifetimeString)) {
            try {
                return Long.parseLong(certLifetimeString);
            } catch (Throwable t) {
                // if it fails, just say so, but keep going.
                myLogger.warn("Error: parsing default lifetime for cert:" + t.getMessage());
            }
        }
        return defaultCertLifetime;
    }


    boolean trivial(String x) {
        return x == null || 0 == x.length();
    }

    public String getId() {
        String id = getCfgValue(ClientXMLTags.ID);
        if (trivial(id)) {
            throw new MyConfigurationException("Error: there is no identifier specified.");
        }
        return id;
    }

    public URI getCallback() {
        String cb = getCfgValue(ClientXMLTags.CALLBACK_URI);
        if (cb == null) {
            return null; // perfectly fine
        }
        return checkURI(cb, "callback");
    }


    /**
     * Fix for OAUTH-107. Check that the protocols are indeed https as per spec at client loading
     * rather than wait for a much later error from a server possibly trying to do a redirect.
     * It is ok for the argument to be null, since that just means that a (correct) address will be created.
     * This is to find mis-specified service addresses.
     *
     * @param b
     */
    protected void checkProtocol(String b) {
        if (b == null) return;
        if (!b.toLowerCase().startsWith("https")) {
            throw new IllegalArgumentException("Error: the " + ClientXMLTags.BASE_URI + " must be https. You have \"" + b + "\"");
        }
    }

    String baseURI = null;

    public String getServiceURI() {
        if (baseURI == null) {
            baseURI = getCfgValue(ClientXMLTags.BASE_URI);
            if (!(baseURI == null || baseURI.length() == 0)) {
                // normalize it so there is no trailing /
                baseURI = baseURI.endsWith("/") ? baseURI.substring(0, baseURI.length() - 1) : baseURI;
                //throw new IllegalArgumentException("Error: no " + ClientXMLTags.BASE_URI + " specified in the configuration file");
                checkProtocol(baseURI);
            }
        }
        return baseURI;
    }

    String wellKnownURI = null;

    public String getWellKnownURI() {
        if (wellKnownURI == null) {
            wellKnownURI = getCfgValue("wellKnownUri");
            if (wellKnownURI == null) {
                // not set, so try to create one
                if (getServiceURI() == null) {
                    //   throw new IllegalStateException("no well-known or " + ClientXMLTags.BASE_URI + " specified in the configuration file");
                } else {
                    wellKnownURI = getServiceURI() + "/.well-known/openid-configuration";
                }
            }
        }
        return wellKnownURI;
    }

    public URI getAccessTokenURI() {

        return createServiceURI(getCfgValue(ClientXMLTags.ACCESS_TOKEN_URI),
                OIDCDiscoveryTags.TOKEN_ENDPOINT_DEFAULT,
                OIDCDiscoveryTags.TOKEN_ENDPOINT);
    }

    public URI getAssetURI() {
        // since this is the really old, non-standanrd getcert endpoint, we cannot look it up
        String x = getCfgValue(ClientXMLTags.ASSET_URI);
        if (x == null) {
            return null; // some system,s just don't use it at all. No reason to require one in the config.
        }
        checkProtocol(x);
        return createServiceURIOLD(x, getServiceURI(), ASSET_ENDPOINT);
    }

    public URI getIssuer(){
        return createServiceURI(getCfgValue(ISSUER_URI),
                OIDCDiscoveryTags.ISSUER,
                OIDCDiscoveryTags.ISSUER);
    }
    public URI getAuthorizeURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.AUTHORIZE_TOKEN_URI),
                OIDCDiscoveryTags.AUTHORIZATION_ENDPOINT_DEFAULT,
                OIDCDiscoveryTags.AUTHORIZATION_ENDPOINT);
    }


    T loader = null;

    public T load() {
        if (loader == null) {
            loader = createInstance();
        }
        return loader;
    }

    SSLConfiguration sslConfiguration = null;

    public SSLConfiguration getSSLConfiguration() {
        if (sslConfiguration == null) {
            sslConfiguration = SSLConfigurationUtil.getSSLConfiguration(myLogger, cn);
        }
        return sslConfiguration;
    }

    public ServiceClient createServiceClient(URI host) {
        return new ServiceClient(host, getSSLConfiguration());
    }

    public ServiceClient getWellKnownClient() {
        if (wellKnownClient == null) {
            wellKnownClient = createServiceClient(URI.create(getWellKnownURI()));
        }
        return wellKnownClient;
    }

    ServiceClient wellKnownClient = null;

    /**
     * Get the given value from the given key on the well-known page. This just return strings.
     * If there is no such value, a null is returned. If the response is incorrect, an exception is
     * thrown.
     *
     * @param key
     * @return
     */
    public String getWellKnownString(String key) {
        if (getWellKnownConfiguration().containsKey(key)) {
            return getWellKnownConfiguration().getString(key);
        }
        return null;
    }

    /**
     * Get a value form the well-known configuration which may be a JSON or other
     * object. You have to process it once you have it.
     *
     * @param key
     * @return
     */
    public Object getWellKnownValue(String key) {
        // This is not used now, but might be useful later for discovery
        if (getWellKnownConfiguration().containsKey(key)) {
            return getWellKnownConfiguration().get(key);
        }
        return null;
    }


    /**
     * The well-known page from the server. Cache this or <i>every</i> call
     * for a configuration value can require a trip to the server. The well-known
     * page should rarely change, so this is completely reasonable.
     *
     * @return
     */
    public JSONObject getWellKnownConfiguration() {
        if (wellKnownConfiguration == null) {
            String response = getWellKnownClient().doGet(new HashMap());// do basic get -- no parameters
            wellKnownConfiguration = JSONObject.fromObject(response);
        }
        return wellKnownConfiguration;
    }

    JSONObject wellKnownConfiguration = null;

}
