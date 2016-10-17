package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/11/16 at  1:57 PM
 */
public class PermissionFileStore<V extends Permission> extends FileStore<V> implements PermissionsStore<V> {
    public PermissionFileStore(File directory, IdentifiableProvider<V> idp, MapConverter<V> cp) {
        super(directory, idp, cp);
    }

    public PermissionFileStore(File storeDirectory, File indexDirectory, IdentifiableProvider<V> identifiableProvider, MapConverter<V> converter) {
        super(storeDirectory, indexDirectory, identifiableProvider, converter);
    }

    @Override
    public List<Identifier> getAdmins(Identifier clientID) {
        return null;
    }

    @Override
    public List<Identifier> getClients(Identifier adminID) {
        return null;
    }

    @Override
    public Permission get(Identifier adminID, Identifier clientID) {
        return null;
    }
    @Override
    public boolean hasEntry(Identifier adminID, Identifier clientID) {
        return get(adminID,clientID) != null;
    }
}

