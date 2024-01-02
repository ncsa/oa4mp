package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientLoaderInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.oa4mp.delegation.client.DelegationService;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.client.*;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.LoggerProvider;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONObject;

import javax.inject.Provider;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

/**
 * Refactoring of the client that has a lot of OAuth 1.0a cruft that just needs to go away, as well as
 * a lot of code that should be centralized.
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/23 at  4:03 PM
 */
public abstract class OA2ClientLoaderImpl<T extends OA2ClientEnvironment> implements ClientLoaderInterface<T> {
    @Override
    public OA2MPServiceProvider getServiceProvider() {
        return new OA2MPServiceProvider(load());
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

    Provider<DelegationService> dsp = null;

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
                                    false), // use basic auth deprecated and always false.
                            new PAServer2(createServiceClient(getAssetURI())),
                            new UIServer2(createServiceClient(getUIURI())),
                            new RTServer2(createServiceClient(getAccessTokenURI()), getIssuer(), getWellKnownURI(), isOIDCEnabled()), // as per spec, refresh token server is at same endpoint as access token server.
                            new RFC7009Server2(createServiceClient(getRFC7009Endpoint()), getIssuer(), getWellKnownURI(), isOIDCEnabled()),
                            new RFC7662Server2(createServiceClient(getRFC7662Endpoint()), getIssuer(), getWellKnownURI(), isOIDCEnabled()),
                            new RFC7523Server(createServiceClient(getAccessTokenURI()), getIssuer(), getWellKnownURI(), isOIDCEnabled()),
                            new RFC8623Server(createServiceClient(getDeviceAuthorizationURI()), getIssuer(), getWellKnownURI(), isOIDCEnabled())
                    );
                }
            };
        }
        return dsp;
    }

    protected URI createServiceURI(String foundURI, String endpoint, String wellKnownEntry) {
        if (!StringUtils.isTrivial(foundURI)) {
            return checkURI(foundURI, wellKnownEntry);
        }
        if (getWellKnownURI() != null) {
            return checkURI(getWellKnownString(wellKnownEntry), wellKnownEntry);
        }
        // failing that, try to construct it
        if (StringUtils.isTrivial(getServiceURI())) {
            //   throw new MyConfigurationException("Error: No base uri for " + endpoint + " found");
            return null;
        }
        return checkURI(getServiceURI() + "/" + endpoint, endpoint);
    }

    /**
     * Checks the uri. The componentName is simply used for a more readable error messages
     * if the uri is trivial or there is some syntax error with it.
     *
     * @param uri
     * @param componentName
     * @return
     */
    protected URI checkURI(String uri, String componentName) {
        if (StringUtils.isTrivial(uri)) {
            throw new MyConfigurationException("Error: There is no " + componentName + " URI specified.");
        }
        try {
            // set it this way rather than with URI.create so we get a recognizable exception to hand back.
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new MyConfigurationException("Error: The specified " + componentName + " is not a valid URI", e);
        }

    }

    protected AssetProvider assetProvider = new OA2AssetProvider();

    public AssetProvider getAssetProvider() {
        return assetProvider;
    }

    protected OA2AssetSerializationKeys assetKeys = new OA2AssetSerializationKeys();
    protected OA2AssetConverter assetConverter = new OA2AssetConverter(assetKeys, assetProvider);
    protected Provider<TokenForge> tokenForgeProvider = new Provider<TokenForge>() {
        @Override
        public TokenForge get() {
            return new OA2TokenForge(getId());
        }
    };
    LoggerProvider loggerProvider = null;

    public abstract LoggerProvider getLoggerProvider();

    /**
     * Checks for and sets up the debugging for this loader. Once this is set up, you may have to tell any environments that
     * use it that debugging is enabled.  Note that this is not used in this module, but in OA4MP proper, but has to b
     * here for visibility later.
     */
    public abstract MetaDebugUtil getDebugger();
    protected MetaDebugUtil getDebugger(String debugLevel) {
            MetaDebugUtil debugger = new MetaDebugUtil();
            try {
                if (debugLevel == null || debugLevel.isEmpty()) {
                    debugger.setDebugLevel(DebugUtil.DEBUG_LEVEL_OFF);
                } else {
                    debugger.setDebugLevel(debugLevel);
                }
                //    debugger.trace(this, ".load: set debug to level " + DebugUtil.getDebugLevel());

            } catch (Throwable t) {
                // ok, so that didn't work, fall back to the old way
                debugger.setIsEnabled(Boolean.parseBoolean(debugLevel));
            }
        return debugger;
    }
}

