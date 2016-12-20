package edu.uiuc.ncsa.myproxy.oa4mp.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore.DSFSClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientStoreTable;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientMemoryStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.ClientKeys;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import edu.uiuc.ncsa.security.oauth_1_0a.client.OAClientProvider;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider.CLIENT_ID;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME;
import static edu.uiuc.ncsa.security.core.util.IdentifierProvider.SCHEME_SPECIFIC_PART;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/15/16 at  1:53 PM
 */
public class ClientStoreProviders {
    public static IdentifiableProviderImpl<? extends Client> getClientProvider() {
        if (clientProvider == null) {
            clientProvider = new OAClientProvider(new OA4MPIdentifierProvider(SCHEME, SCHEME_SPECIFIC_PART, CLIENT_ID, false));
        }
        return clientProvider;
    }

    protected static IdentifiableProviderImpl<? extends Client> clientProvider;

    static MapConverter<? extends Client> clientConverter;

    public static MapConverter<? extends Client> getClientConverter() {
        if (clientConverter == null) {
            clientConverter = new ClientConverter(getClientProvider());
        }
        return clientConverter;
    }

    public static void setClientConverter(MapConverter<? extends Client> cc) {
        clientConverter = cc;
    }

    public static class DSFSClientStoreProvider extends FSProvider<DSFSClientStore> implements OA4MPConfigTags {

        public DSFSClientStoreProvider(ConfigurationNode config,
                                       MapConverter<? extends Client> cp,
                                       Provider<? extends Client> clientProvider) {
            super(config, FILE_STORE, CLIENTS_STORE, cp);
            this.clientProvider = clientProvider;
        }

        Provider<? extends Client> clientProvider;

        @Override
        protected DSFSClientStore produce(File dataPath, File indexPath) {
            return new DSFSClientStore(dataPath, indexPath, (IdentifiableProviderImpl<Client>) clientProvider, converter);
        }
    }

    public static FSProvider<? extends ClientStore> getFSP(ConfigurationNode node) {
        return new DSFSClientStoreProvider(node, getClientConverter(), getClientProvider());
    }

    public static class DSClientSQLStoreProvider<V extends SQLClientStore> extends SQLStoreProvider<V> {
        protected Provider<? extends Client> clientProvider;

        public DSClientSQLStoreProvider(ConfigurationNode cn, ConnectionPoolProvider<? extends ConnectionPool> cpp, String type
        ) {
            super(cn, cpp, type, OA4MPConfigTags.CLIENTS_STORE, SQLClientStore.DEFAULT_TABLENAME, getClientConverter());
            this.clientProvider = getClientProvider();
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

    public static DSClientSQLStoreProvider<? extends SQLClientStore> getMysqlPS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
        return new DSClientSQLStoreProvider(node, cpp, OA4MPConfigTags.MYSQL_STORE);
    }

    public static DSClientSQLStoreProvider<? extends SQLClientStore> getMariaDBPS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
        return new DSClientSQLStoreProvider(node, cpp, OA4MPConfigTags.MARIADB_STORE);
    }

    public static DSClientSQLStoreProvider<? extends SQLClientStore> getPostgresPS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
        return new DSClientSQLStoreProvider(node, cpp, OA4MPConfigTags.POSTGRESQL_STORE);
    }

    public static MemoryClientStoreProvider<? extends Client> getM(ConfigurationNode node){
        return new MemoryClientStoreProvider<>(node);
    }
    public static class MemoryClientStoreProvider<V extends Client> extends TypedProvider<ClientStore<V>> {
        public MemoryClientStoreProvider(ConfigurationNode config) {
            super(config, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.CLIENTS_STORE);
        }

        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            if (checkEvent(configurationEvent)) {
                return get();
            }
            return null;
        }

        @Override
        public ClientStore get() {
            return new ClientMemoryStore(getClientProvider());
        }
    }
}
