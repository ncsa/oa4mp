package org.oa4mp.client.api;

import org.oa4mp.client.api.storage.AssetStore;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * An interface ensuring that loaders have a service provider.
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/12 at  10:52 AM
 */
public interface ClientLoaderInterface<T extends ClientEnvironment> extends ConfigurationLoader<T> {
    /**
     * The provider that creates an instance of the {@link OA4MPService}
     *
     * @return
     */
    public OA4MPServiceProvider getServiceProvider();

    Collection<String> getScopes();

    JSONWebKeys getKeys();

    Map<String, List<String>> getAdditionalParameters();

    Provider<AssetStore> getAssetStoreProvider();

    SSLConfiguration getSSLConfiguration();

    String getId();

    String getKID();

    String getSecret();

    String getServiceURI();

    String getSkin();

    String getWellKnownURI();

    URI getAccessTokenURI();

    URI getAssetURI();

    URI getAuthorizeURI();

    URI getCallback();

    URI getDeviceAuthorizationURI();

    URI getRFC7009Endpoint();

    URI getUIURI();

    boolean isEnableAssetCleanup();

    boolean isOIDCEnabled();

    long getCertLifetime();

    long getKeypairLifetime();

    long getMaxAssetLifetime();

    URI getRFC7662Endpoint();

    URI getIssuer();
}
