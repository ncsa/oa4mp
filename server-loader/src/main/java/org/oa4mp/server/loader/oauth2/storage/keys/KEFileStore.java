package org.oa4mp.server.loader.oauth2.storage.keys;


import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;

import java.io.File;
import java.util.HashSet;
import java.util.List;

public class KEFileStore<V extends KERecord> extends FileStore<V> implements KEStore<V> {
    public KEFileStore(File storeDirectory, File indexDirectory, IdentifiableProvider<V> identifiableProvider, MapConverter<V> converter, boolean removeEmptyFiles, boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles, removeFailedFiles);
    }

    public KEFileStore(File directory, IdentifiableProvider<V> idp, MapConverter<V> cp, boolean removeEmptyFiles, boolean removeFailedFiles) {
        super(directory, idp, cp, removeEmptyFiles, removeFailedFiles);
    }

    @Override
    public KEConverter<V> getXMLConverter() {
        return (KEConverter<V>) super.getMapConverter();
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }

    @Override
    public KERecord getByKID(String kid) {
        return KEStoreUtilities.getByKID(this, kid);
    }

    @Override
    public HashSet<String> getKIDs() {
        return KEStoreUtilities.getKIDs(this);
    }

    @Override
    public JSONWebKeys getCurrentKeys(VirtualIssuer vi) {
        return null;
    }
}
