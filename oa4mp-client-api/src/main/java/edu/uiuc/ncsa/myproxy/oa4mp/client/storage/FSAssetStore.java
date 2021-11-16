package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/28/13 at  1:14 PM
 */
public class FSAssetStore extends FileStore<Asset> implements AssetStore {
    public FSAssetStore(File file,
                        IdentifiableProvider idp,
                        MapConverter cp,
                        boolean removeEmptyFiles) {
        super(file, idp, cp, removeEmptyFiles);
    }

    public FSAssetStore(File storeDirectory,
                        File indexDirectory,
                        IdentifiableProvider identifiableProvider,
                        MapConverter converter,
                        boolean removeEmptyFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles);
    }

    @Override
    public Asset get(String identifier) {
        return AssetStoreUtil.get(identifier, this);
    }

    @Override
    public void save(String identifier, Asset identifiable) {
        AssetStoreUtil.save(identifier, identifiable, this);
    }

    @Override
    public void realSave(boolean checkExists, Asset t) {
        super.realSave(checkExists, t);
        try {
            if (t.getToken() != null) {
                createIndexEntry(t.getToken().toString(), t.getIdentifierString());
            }
        } catch (IOException e) {
            throw new GeneralException("Error serializing item " + t + "to file ");
        }
    }


    @Override
    public Asset getByToken(Identifier token) {
        return  getIndexEntry(token.toString());
    }

    @Override
    public void putByToken(Asset asset) {
        realSave(false, asset); // just save this which updates the index.
    }

    @Override
    public List<Asset> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }
}
