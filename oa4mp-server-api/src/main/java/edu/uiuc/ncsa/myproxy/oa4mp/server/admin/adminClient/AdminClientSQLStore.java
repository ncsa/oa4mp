package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:52 PM
 */
public class AdminClientSQLStore<V extends AdminClient> extends SQLStore<V> implements AdminClientStore<V> {
    public static final String DEFAULT_TABLENAME = "adminClients";
    public AdminClientSQLStore() {
    }

    public AdminClientSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public AdminClientConverter getACConverter() {
        return (AdminClientConverter) this.converter;
    }

    @Override
    public IdentifiableProvider getACProvider() {
        return (IdentifiableProvider) this.identifiableProvider;
    }
}
