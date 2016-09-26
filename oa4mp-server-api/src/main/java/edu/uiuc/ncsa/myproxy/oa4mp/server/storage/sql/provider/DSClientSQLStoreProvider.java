package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientStoreTable;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.ClientKeys;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  3:18 PM
 */
public class DSClientSQLStoreProvider<V extends SQLClientStore> extends SQLStoreProvider<V> {
     public DSClientSQLStoreProvider(ConnectionPoolProvider<? extends ConnectionPool> cpp, String type, MapConverter converter,
                                     Provider<? extends Client> clientProvider) {
        super(null, cpp, type, OA4MPConfigTags.CLIENTS_STORE, SQLClientStore.DEFAULT_TABLENAME, converter);
         this.clientProvider = clientProvider;
    }

   protected Provider<? extends Client> clientProvider;
    public DSClientSQLStoreProvider(ConfigurationNode cn, ConnectionPoolProvider<? extends ConnectionPool> cpp, String type,
                                    MapConverter converter, Provider<? extends Client> clientProvider) {
    super(cn, cpp, type, OA4MPConfigTags.CLIENTS_STORE, SQLClientStore.DEFAULT_TABLENAME, converter);
        this.clientProvider = clientProvider;
    }

    @Override
    public V newInstance(Table table) {
        return (V) new SQLClientStore(getConnectionPool(), table, clientProvider, converter);
    }

    @Override
    public V get() {
        ClientStoreTable cst = new ClientStoreTable(
                new ClientKeys(),
                getSchema(), getPrefix(), getTablename());
        return newInstance(cst);
    }
}
