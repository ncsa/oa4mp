package org.oa4mp.server.api.storage.sql.provider;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.clients.ClientConverter;
import org.oa4mp.delegation.common.storage.clients.ClientKeys;
import org.oa4mp.delegation.common.storage.clients.ClientProvider;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.storage.sql.SQLClientStore;
import org.oa4mp.server.api.storage.sql.table.ClientStoreTable;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  3:18 PM
 */
public class DSClientSQLStoreProvider<V extends SQLClientStore> extends SQLStoreProvider<V> {
     public DSClientSQLStoreProvider(ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                     String type,
                                     MapConverter converter,
                                     Provider<? extends Client> clientProvider) {
        super((CFNode)null, cpp, type, OA4MPConfigTags.CLIENTS_STORE, SQLClientStore.DEFAULT_TABLENAME, converter);
         this.clientProvider = clientProvider;
    }

    public DSClientSQLStoreProvider(CFNode config,
                                    ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                    String type,
                                    String target,
                                    MapConverter converter,
                                    Provider<? extends Client> clientProvider) {
        super(config, cpp, type, target, converter);
        this.clientProvider = clientProvider;
    }

    public DSClientSQLStoreProvider(CFNode config,
                                    ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                    String type,
                                    String target,
                                    String tablename,
                                    MapConverter converter,
                                    Provider<? extends Client> clientProvider) {
        super(config, cpp, type, target, tablename, converter);
        this.clientProvider = clientProvider;
    }

    public DSClientSQLStoreProvider(CFNode cn,
                                    ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                    String type,
                                    ClientConverter converter,
                                    ClientProvider clientProvider) {
        super(cn, cpp, type, OA4MPConfigTags.CLIENTS_STORE, SQLClientStore.DEFAULT_TABLENAME, converter);
        this.clientProvider = clientProvider;

    }

    protected Provider<? extends Client> clientProvider;


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
