package edu.uiuc.ncsa.myproxy.oa4mp.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientLoaderInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.oa4mp.delegation.client.DelegationService;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.DBConfigLoader;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.net.URI;
import java.net.URISyntaxException;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags.*;

/**
 * Top-level class for client loader that creates asset store and controls which classes are instantiated for the client.
 * <p>Created by Jeff Gaynor<br>
 * on 11/25/13 at  1:12 PM
 */
public abstract class AbstractClientLoader<T extends ClientEnvironment> extends DBConfigLoader<T> implements ClientLoaderInterface {
    public static final String ACCESS_TOKEN_ENDPOINT = "token";
    public static final String AUTHORIZE_ENDPOINT = "authorize";
    public static final String ASSET_ENDPOINT = "getcert";
    public static final String INITIATE_ENDPOINT = "initiate";
    public static final String USER_INFO_ENDPOINT = "userinfo";
    public static final String INTROSPECTION_ENDPOINT = "introspect";
    public static final String REVOCATION_ENDPOINT = "revoke";
    public static final String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization"; // suggested in the spec, best guess for default.


    // FIX for OAUTH-137. Set default cert lifetime to be 12 hours, not 10 days.
    public static final long defaultCertLifetime = 43200L; // default is 12 hours, in seconds.


    protected AbstractClientLoader(ConfigurationNode node) {
        super(node);
    }

    protected AbstractClientLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    protected Provider<AssetStore> assetStoreProvider;


    public abstract AssetProvider getAssetProvider();

    protected Provider<AssetStore> getAssetStoreProvider() {
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


    protected URI checkURI(String x, String componentName) {
        if (trivial(x)) {
            throw new MyConfigurationException("Error: There is no " + componentName + " URI specified.");
        }
        try {
            // set it this way rather than with URI.create so we get a recognizable exception to hand back.
            return new URI(x);
        } catch (URISyntaxException e) {
            throw new MyConfigurationException("Error: The specified " + componentName + " is not a valid URI", e);
        }

    }

    /**
     * This takes a key and returns the value of the node associated with that key.
     *
     * @param key
     * @return
     */
    protected String getCfgValue(String key) {
        return Configurations.getNodeValue(cn, key);
    }


    protected String getSkin() {
        return getCfgValue(SKIN);
    }

    protected long getKeypairLifetime() {
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

    protected long getMaxAssetLifetime() {
        String x = getCfgValue(MAX_ASSET_LIFETIME);
        long y = 30 * 24 * 3600000L; // set it for a month in milliseconds
        if (x == null || x.length() == 0) return y;
        try {
            // The value in the file is assumed to be in seconds.
            y = Long.parseLong(x) * 1000L;
        } catch (NumberFormatException nfx) {
            // use default...
        }
        return y;
    }

    protected boolean isEnableAssetCleanup() {
        boolean doIt = false;
        try {
            doIt = Boolean.parseBoolean(getCfgValue(ENABLE_ASSET_CLEANUP));
        } catch (Throwable t) {
            // do nothing....
        }
        return doIt;
    }


    /**
     * Checks if there is a found uri in the configuration. If so, check that and use it,
     * if not, try and construct the service endpoint from the base uri.
     *
     * @param foundURI
     * @param baseUri
     * @param serviceEndpoint
     * @return
     */
    protected URI createServiceURI(String foundURI, String baseUri, String serviceEndpoint) {
        if (!trivial(foundURI)) {
            return checkURI(foundURI, serviceEndpoint);
        }
        if (trivial(baseUri)) {
            throw new MyConfigurationException("Error: No base uri for " + serviceEndpoint + " found");
        }
        return checkURI(baseUri + (baseUri.endsWith("/") ? "" : "/") + serviceEndpoint, serviceEndpoint);
    }

    protected long checkCertLifetime() {
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

    protected String getId() {
        String id = getCfgValue(ClientXMLTags.ID);
        if (trivial(id)) {
            throw new MyConfigurationException("Error: there is no identifier specified.");
        }
        return id;
    }

    protected URI getCallback() {
        return checkURI(getCfgValue(ClientXMLTags.CALLBACK_URI), "callback");
    }


    /**
     *  Fix for OAUTH-107. Check that the protocols are indeed https as per spec at client loading
     *  rather than wait for a much later error from a server possibly trying to do a redirect.
     *  It is ok for the argument to be null, since that just means that a (correct) address will be created.
     *  This is to find mis-specified service addresses.

     * @param b
     */
    protected void checkProtocol(String b) {
        if(b == null) return;
        if (!b.toLowerCase().startsWith("https")) {
            throw new IllegalArgumentException("Error: the base uri must be https. You have \"" + b + "\"");
        }
    }

    protected String getBaseURI() {
        String b = getCfgValue(ClientXMLTags.BASE_URI);
        if (b == null || b.length() == 0) {
            throw new IllegalArgumentException("Error: no base uri specified in the configuration file");
        }
        checkProtocol(b);
        return b;
    }

    protected URI getAccessTokenURI() {
        return createServiceURI(getCfgValue(ClientXMLTags.ACCESS_TOKEN_URI), getBaseURI(), ACCESS_TOKEN_ENDPOINT);
    }

    protected URI getAssetURI() {
        String x = getCfgValue(ClientXMLTags.ASSET_URI);
        checkProtocol(x);
        return createServiceURI(x, getBaseURI(), ASSET_ENDPOINT);
    }

    protected URI getAuthorizeURI() {
        String x = getCfgValue(ClientXMLTags.AUTHORIZE_TOKEN_URI);
        checkProtocol(x);
        return createServiceURI(x, getBaseURI(), AUTHORIZE_ENDPOINT);
    }

    protected URI getInitiateURI() {
        String x = getCfgValue(ClientXMLTags.INITIATE_URI);
        checkProtocol(x);
        return createServiceURI(x, getBaseURI(), INITIATE_ENDPOINT);
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


}
