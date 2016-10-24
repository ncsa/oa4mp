package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:50 PM
 */
public class AdminClientStoreProviders {
    protected static IdentifiableProviderImpl<? extends AdminClient> adminClientProvider;
    protected static AdminClientConverter<? extends AdminClient> adminClientConverter;
    protected static AdminClientKeys adminClientKeys;

    public static AdminClientKeys getAdminClientKeys() {
        if (adminClientKeys == null) {
            adminClientKeys = new AdminClientKeys();
        }
        return adminClientKeys;
    }

    public static void setAdminClientKeys(AdminClientKeys adminClientKeys) {
        AdminClientStoreProviders.adminClientKeys = adminClientKeys;
    }


    public static AdminClientConverter<? extends AdminClient> getAdminClientConverter() {
        if (adminClientConverter == null) {
            adminClientConverter = new AdminClientConverter<>(getAdminClientKeys(), getAdminClientProvider());
        }
        return adminClientConverter;
    }

    public static void setAdminClientConverter(AdminClientConverter<? extends AdminClient> adminClientConverter) {
        AdminClientStoreProviders.adminClientConverter = adminClientConverter;
    }

    public static IdentifiableProviderImpl<? extends AdminClient> getAdminClientProvider() {
        if (adminClientProvider == null) {
            adminClientProvider = new AdminClientProvider<>();
        }
        return adminClientProvider;
    }

    public static void setAdminClientProvider(IdentifiableProviderImpl<? extends AdminClient> adminClientProvider) {
        AdminClientStoreProviders.adminClientProvider = adminClientProvider;
    }

    public static class AdminClientFSProvider extends FSProvider<AdminClientFS> implements OA4MPConfigTags {

        public AdminClientFSProvider(ConfigurationNode config) {
            super(config, FILE_STORE, ADMIN_CLIENT_STORE, getAdminClientConverter());
        }


        @Override
        protected AdminClientFS produce(File dataPath, File indexPath) {
            return new AdminClientFS(dataPath, indexPath, getAdminClientProvider(), getAdminClientConverter());
        }

    }

    public static AdminClientFSProvider getACFSP(ConfigurationNode node) {
        return new AdminClientFSProvider(node);
    }


    public static class AdminClientMSProvider extends TypedProvider<AdminClientMemoryStore> implements OA4MPConfigTags {
        public AdminClientMSProvider(ConfigurationNode node) {
            super(node, MEMORY_STORE, ADMIN_CLIENT_STORE);
        }

        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            return null;
        }

        @Override
        public AdminClientMemoryStore get() {
            return new AdminClientMemoryStore(getAdminClientProvider());
        }
    }

    public static AdminClientMSProvider getACMP(ConfigurationNode node) {
        return new AdminClientMSProvider(node);
    }

    public static class AdminClientSQLStoreProvider extends SQLStoreProvider<AdminClientSQLStore> implements OA4MPConfigTags {
        public AdminClientSQLStoreProvider(ConfigurationNode config, String type,
                                           ConnectionPoolProvider<? extends ConnectionPool> cpp) {
            super(config, cpp, type, ADMIN_CLIENT_STORE, AdminClientSQLStore.DEFAULT_TABLENAME, getAdminClientConverter());
        }

        @Override
        public AdminClientSQLStore newInstance(Table table) {
            AdminClientSQLStore store = new AdminClientSQLStore(getConnectionPool(), table, getAdminClientProvider(), converter);
            return store;
        }

        @Override
        public AdminClientSQLStore get() {
            return newInstance(new AdminClientTable(getAdminClientKeys(), getSchema(), getPrefix(), getTablename()));
        }
    }

    public static AdminClientSQLStoreProvider getMariaACS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new AdminClientSQLStoreProvider(node, OA4MPConfigTags.MARIADB_STORE, cpp);
    }
    public static AdminClientSQLStoreProvider getMysqlACS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new AdminClientSQLStoreProvider(node, OA4MPConfigTags.MYSQL_STORE, cpp);
    }
    public static AdminClientSQLStoreProvider getPostgresACS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new AdminClientSQLStoreProvider(node, OA4MPConfigTags.POSTGRESQL_STORE, cpp);
    }

}
