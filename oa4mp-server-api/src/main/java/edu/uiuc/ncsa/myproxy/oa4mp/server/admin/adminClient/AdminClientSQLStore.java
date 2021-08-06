package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.delegation.server.storage.BaseClientSQLStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:52 PM
 */
public class AdminClientSQLStore<V extends AdminClient> extends BaseClientSQLStore<V> implements AdminClientStore<V> {
    public static final String DEFAULT_TABLENAME = "adminClients";
  
    public AdminClientSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }


    @Override
    public void save(V value) {
        value.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.save(value);
    }
}
