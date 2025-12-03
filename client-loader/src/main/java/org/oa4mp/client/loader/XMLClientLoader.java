package org.oa4mp.client.loader;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import org.oa4mp.client.api.ClientLoaderInterface;
import org.oa4mp.client.api.OA4MPServiceProvider;
import org.oa4mp.client.api.storage.AssetStore;

import javax.inject.Provider;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *  Facade for the old loader so that it acts like the new loader.
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/23 at  4:04 PM
 */
public class XMLClientLoader<T extends OA2ClientEnvironment> implements ClientLoaderInterface<T> {

    public XMLClientLoader(CFNode node) {
           oldLoader = new OA2CFClientLoader<>(node);
    }

    public OA2CFClientLoader getOldLoader() {
        return oldLoader;
    }

    public void setOldLoader(OA2CFClientLoader oldLoader) {
        this.oldLoader = oldLoader;
    }

    OA2CFClientLoader oldLoader;

    @Override
    public OA4MPServiceProvider getServiceProvider() {
        return getOldLoader().getServiceProvider();
    }

    @Override
    public Collection<String> getScopes() {
        return getOldLoader().getScopes();
    }

    @Override
    public JSONWebKeys getKeys() {
        return getOldLoader().getKeys();
    }

    @Override
    public Map<String, List<String>> getAdditionalParameters() {
        return getOldLoader().getAdditionalParameters();
    }

    @Override
    public Provider<AssetStore> getAssetStoreProvider() {
        return getOldLoader().getAssetStoreProvider();
    }

    @Override
    public SSLConfiguration getSSLConfiguration() {
        return getOldLoader().getSSLConfiguration();
    }

    @Override
    public String getId() {
        return getOldLoader().getId();
    }

    @Override
    public String getKID() {
        return getOldLoader().getKID();
    }

    @Override
    public String getSecret() {
        return getOldLoader().getSecret();
    }

    @Override
    public String getServiceURI() {
        return getOldLoader().getServiceURI();
    }

    @Override
    public String getSkin() {
        return getOldLoader().getSkin();
    }

    @Override
    public String getWellKnownURI() {
        return getOldLoader().getWellKnownURI();
    }

    @Override
    public URI getAccessTokenURI() {
        return getOldLoader().getAccessTokenURI();
    }

    @Override
    public URI getAssetURI() {
        return getOldLoader().getAssetURI();
    }

    @Override
    public URI getAuthorizeURI() {
        return getOldLoader().getAuthorizeURI();
    }

    @Override
    public URI getCallback() {
        return getOldLoader().getCallback();
    }

    @Override
    public URI getDeviceAuthorizationURI() {
        return getOldLoader().getDeviceAuthorizationURI();
    }

    @Override
    public URI getRFC7009Endpoint() {
        return getOldLoader().getRFC7009Endpoint();
    }

    @Override
    public URI getUIURI() {
        return getOldLoader().getUIURI();
    }

    @Override
    public boolean isEnableAssetCleanup() {
        return getOldLoader().isEnableAssetCleanup();
    }

    @Override
    public boolean isOIDCEnabled() {
        return getOldLoader().isOIDCEnabled();
    }

    @Override
    public long getCertLifetime() {
        return getOldLoader().getCertLifetime();
    }

    @Override
    public long getKeypairLifetime() {
        return getOldLoader().getKeypairLifetime();
    }

    @Override
    public long getMaxAssetLifetime() {
        return getOldLoader().getMaxAssetLifetime();
    }

    @Override
    public URI getRFC7662Endpoint() {
        return getOldLoader().getRFC7662Endpoint();
    }

    @Override
    public T load() {
        return (T) getOldLoader().load();
    }

    @Override
    public T createInstance() {
        return (T) getOldLoader().createInstance();
    }

    @Override
    public HashMap<String, String> getConstants() {
        return getOldLoader().getConstants();
    }

    @Override
    public URI getIssuer() {
        return getOldLoader().getIssuer();
    }
}
