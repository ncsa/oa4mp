package org.oa4mp.server.loader.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  9:02 AM
 */
public class TXFileStore<V extends TXRecord> extends FileStore<V> implements TXStore<V> {
    public TXFileStore(File storeDirectory,
                       File indexDirectory,
                       IdentifiableProvider<V> identifiableProvider,
                       MapConverter<V> converter,
                       boolean removeEmptyFiles,
                       boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles,removeFailedFiles);
    }

    public TXFileStore(File directory,
                       IdentifiableProvider<V> idp,
                       MapConverter<V> cp,
                       boolean removeEmptyFiles,
                       boolean removeFailedFiles) {
        super(directory, idp, cp, removeEmptyFiles,removeFailedFiles);
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public List<V> getByParentID(Identifier parentID) {
        List<V> kids = new ArrayList<>();
        for (V tx : values()) {
            if (tx.parentID.equals(parentID)) {
                kids.add(tx);
            }
        }
        return kids;
    }
    @Override
    public List<Identifier> getIDsByParentID(Identifier parentID) {
        List<Identifier> kids = new ArrayList<>();
        for(V tx : values()){
            if(tx.parentID.equals(parentID)){
                kids.add(tx.getIdentifier());
            }
        }
        return kids;
    }
    @Override
    public int getCountByParent(Identifier parentID) {
        return getByParentID(parentID).size();
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }
}
