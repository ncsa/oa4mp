package org.oa4mp.server.api.admin.permissions;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import org.oa4mp.server.api.OA4MPConfigTags;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/19/16 at  12:01 PM
 */
public class PermissionStoreProviders {

    public static IdentifiableProviderImpl<? extends Permission> getPermissionProvider() {
        if (permissionProvider == null) {
            permissionProvider = new PermissionProvider<>();
        }
        return permissionProvider;
    }

    public static void setPermissionProvider(IdentifiableProviderImpl<? extends Permission> permissionProvider) {
        PermissionStoreProviders.permissionProvider = permissionProvider;
    }

    protected static IdentifiableProviderImpl<? extends Permission> permissionProvider;

    public static PermissionConverter<? extends Permission> getPermissionConverter() {
        if (permissionConverter == null) {
            permissionConverter = new PermissionConverter<>(new PermissionKeys(), getPermissionProvider());
        }
        return permissionConverter;
    }

    public static void setPermissionConverter(PermissionConverter<? extends Permission> permissionConverter) {
        PermissionStoreProviders.permissionConverter = permissionConverter;
    }

    protected static PermissionConverter<? extends Permission> permissionConverter;

    public static class FSPermissionStoreProvider extends FSProvider<PermissionFileStore> implements OA4MPConfigTags {
        public FSPermissionStoreProvider(CFNode config) {
            super(config, FILE_STORE, PERMISSION_STORE, getPermissionConverter());
        }


        @Override
        protected PermissionFileStore produce(File dataPath, File indexPath, boolean removeEmptyFiles, boolean removeFailedFiles) {
            return new PermissionFileStore(dataPath, indexPath, getPermissionProvider(), converter, removeEmptyFiles,removeFailedFiles);
        }
    }


    public static FSPermissionStoreProvider getFSP(CFNode node) {
        return new FSPermissionStoreProvider(node);
    }

    public static SQLPermissionStoreProvider getMariaPS(CFNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new SQLPermissionStoreProvider(node, OA4MPConfigTags.MARIADB_STORE, cpp);
    }

    public static SQLPermissionStoreProvider getPostgresPS(CFNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new SQLPermissionStoreProvider(node, OA4MPConfigTags.POSTGRESQL_STORE, cpp);
    }

    public static SQLPermissionStoreProvider getDerbyPS(CFNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new SQLPermissionStoreProvider(node, OA4MPConfigTags.DERBY_STORE, cpp);
    }

    public static SQLPermissionStoreProvider getMysqlPS(CFNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp ){
        return new SQLPermissionStoreProvider(node, OA4MPConfigTags.MYSQL_STORE, cpp);
    }


    public static class SQLPermissionStoreProvider extends SQLStoreProvider<SQLPermissionStore> implements OA4MPConfigTags {
        public SQLPermissionStoreProvider(CFNode config, String type,
                                          ConnectionPoolProvider<? extends ConnectionPool> cpp ) {
            super(config, cpp, type, OA4MPConfigTags.PERMISSION_STORE, SQLPermissionStore.DEFAULT_TABLENAME, getPermissionConverter());
        }

        @Override
        public SQLPermissionStore newInstance(Table table) {
            SQLPermissionStore store =new SQLPermissionStore(getConnectionPool(),table, getPermissionProvider(),converter);
            return store;
        }

        @Override
        public SQLPermissionStore get() {
            return newInstance(new PermissionsTable(new PermissionKeys(),getSchema(),getPrefix(),getTablename()));
        }
    }

    public static class MemoryPermissionStoreProvider<V> extends TypedProvider<PermissionMemoryStore> implements OA4MPConfigTags {
        public MemoryPermissionStoreProvider(CFNode config) {
            super(config, OA4MPConfigTags.MEMORY_STORE, OA4MPConfigTags.PERMISSION_STORE);
        }


        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            // Fixes CIL-1014 -- this was returning null.
            if (checkEvent(configurationEvent)) {
                return get();
            }
            
            return null;
        }

        @Override
        public PermissionMemoryStore get() {
            return new PermissionMemoryStore(getPermissionProvider());
        }
    }

    public static MemoryPermissionStoreProvider<? extends PermissionMemoryStore> getM(CFNode node) {
        MemoryPermissionStoreProvider<? extends PermissionMemoryStore> mpp = new MemoryPermissionStoreProvider<>(node);
        return mpp;
    }
}
