package org.oa4mp.client.api.storage;

import org.oa4mp.client.api.Asset;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.MemoryStore;

import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/28/13 at  3:07 PM
 */
public class MemoryAssetStore extends MemoryStore<Asset> implements AssetStore {
    public MemoryAssetStore(IdentifiableProvider<Asset> identifiableProvider) {
        super(identifiableProvider);
    }

    @Override
    public Asset get(String identifier) {
        return AssetStoreUtil.get(identifier, this);
    }

    @Override
    public void save(String identifier, Asset v) {
       AssetStoreUtil.save(identifier, v, this);
    }

    HashMap<Identifier, Asset> tokenCache = new HashMap<>();
    @Override
    public Asset getByToken(Identifier token) {
        return tokenCache.get(token);
    }

    @Override
    public void putByToken(Asset asset) {
            tokenCache.put(asset.getToken(), asset);
    }

    @Override
    public void save(Asset value) {
        super.save(value);
        if(value.getToken() != null){
            putByToken(value);
        }
    }

    @Override
    public XMLConverter<Asset> getXMLConverter() {
        return new AssetConverter(new AssetSerializationKeys(), identifiableProvider);
    }

    @Override
    public List<Asset> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n,attributes);
    }
}

