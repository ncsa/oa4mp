package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/13/16 at  3:58 PM
 */
public class SQLPermissionStore<V extends Permission> extends SQLStore<V> implements PermissionsStore<V> {
    public static String DEFAULT_TABLENAME="permissions";

    public SQLPermissionStore() {
    }

    public SQLPermissionStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public Permission get(Identifier adminID, Identifier clientID) {
        return null;
    }

    @Override
    public List<Identifier> getClients(Identifier adminID) {
        return null;
    }

    @Override
    public List<Identifier> getAdmins(Identifier clientID) {
        return null;
    }

    @Override
    public boolean hasEntry(Identifier adminID, Identifier clientID) {
        return get(adminID,clientID) != null;
    }
}
