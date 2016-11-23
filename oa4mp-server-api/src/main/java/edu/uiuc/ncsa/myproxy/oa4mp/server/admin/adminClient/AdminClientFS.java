package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:51 PM
 */
public class AdminClientFS<V extends AdminClient> extends FileStore<V> implements AdminClientStore<V> {
    public AdminClientFS(File directory, IdentifiableProvider<V> idp, MapConverter<V> cp) {
        super(directory, idp, cp);
    }

    public AdminClientFS(File storeDirectory, File indexDirectory, IdentifiableProvider<V> identifiableProvider, MapConverter<V> converter) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter);

    }

    @Override
    public AdminClientConverter getACConverter() {
        return (AdminClientConverter)this.converter;
    }

    @Override
    public IdentifiableProvider getACProvider() {
        return this.identifiableProvider;
    }
}
