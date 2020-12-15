package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  9:02 AM
 */
public class TXFileStore <V extends TXRecord> extends FileStore<V> implements TXStore<V> {
    public TXFileStore(File storeDirectory,
                       File indexDirectory,
                       IdentifiableProvider<V> identifiableProvider,
                       MapConverter<V> converter,
                       boolean removeEmptyFiles) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter, removeEmptyFiles);
    }

    public TXFileStore(File directory,
                       IdentifiableProvider<V> idp,
                       MapConverter<V> cp,
                       boolean removeEmptyFiles) {
        super(directory, idp, cp, removeEmptyFiles);
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }
}
