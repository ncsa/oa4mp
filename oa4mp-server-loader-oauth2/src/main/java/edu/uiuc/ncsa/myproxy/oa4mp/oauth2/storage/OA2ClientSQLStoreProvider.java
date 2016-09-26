package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider.DSClientSQLStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientStoreTable;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientKeys;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/17/14 at  2:59 PM
 */
public class OA2ClientSQLStoreProvider<V extends SQLClientStore> extends DSClientSQLStoreProvider<V> {
    public OA2ClientSQLStoreProvider(ConnectionPoolProvider<? extends ConnectionPool> cpp, String type, MapConverter converter, Provider<? extends Client> clientProvider) {
        super(cpp, type, converter, clientProvider);
    }

    @Override
    public V newInstance(Table table) {
        return (V) new SQLClientStore<OA2Client>(getConnectionPool(), table, (Provider<OA2Client>) clientProvider, converter);
    }
    @Override
       public V get() {
        ClientStoreTable cst = new OA2ClientTable(
                   new OA2ClientKeys(),
                   getSchema(),
                   getPrefix(),
                   getTablename());
           return newInstance(cst);
       }
}
