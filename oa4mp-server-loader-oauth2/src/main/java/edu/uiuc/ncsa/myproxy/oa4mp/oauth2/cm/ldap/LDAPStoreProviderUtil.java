package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  8:19 AM
 */
public class LDAPStoreProviderUtil {
    public static final String LDAP_STORE = "ldap";
    static LDAPEntryKeys keys;
    static LDAPEntryConverter converter;

    public static LDAPEntryProvider getLdapEntryProvider() {
        if(ldapEntryProvider == null){
            ldapEntryProvider = new LDAPEntryProvider();
        }
        return ldapEntryProvider;
    }


    static LDAPEntryProvider ldapEntryProvider;

    public static LDAPEntryConverter getConverter() {
        if(converter == null){
            converter = new LDAPEntryConverter(getKeys(), getLdapEntryProvider());
        }
        return converter;
    }

    public static void setConverter(LDAPEntryConverter converter) {
        LDAPStoreProviderUtil.converter = converter;
    }

    public static LDAPEntryKeys getKeys() {
        if(keys == null){
            keys = new LDAPEntryKeys();
        }
        return keys;
    }

    public static void setKeys(LDAPEntryKeys keys) {
        LDAPStoreProviderUtil.keys = keys;
    }

    public static FSLDAPStoreProvider getFSP(ConfigurationNode node) {
        return new FSLDAPStoreProvider(node);
    }

    public static class FSLDAPStoreProvider extends FSProvider<LDAPFileStore> implements OA4MPConfigTags {
        public FSLDAPStoreProvider(ConfigurationNode config) {
            super(config, OA4MPConfigTags.FILE_STORE, LDAP_STORE, getConverter());
        }

        @Override
        protected LDAPFileStore produce(File dataPath, File indexPath) {
            return new LDAPFileStore(dataPath, indexPath, getLdapEntryProvider(), getConverter());

        }
    }


    public static MemoryLDAPStoreProvider<? extends LDAPStore> getM(ConfigurationNode node) {
        return new MemoryLDAPStoreProvider<>(node);
    }

    public static class MemoryLDAPStoreProvider<V> extends TypedProvider<LDAPMemoryStore> implements OA4MPConfigTags {
        public MemoryLDAPStoreProvider(ConfigurationNode config) {
            super(config, OA4MPConfigTags.MEMORY_STORE, LDAP_STORE);
        }

        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            return null;
        }

        @Override
        public LDAPMemoryStore get() {
            return new LDAPMemoryStore(getLdapEntryProvider());
        }
    }

    public static SQLLDAPStoreProvider getMariaDB(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
        return new SQLLDAPStoreProvider(node, OA4MPConfigTags.MARIADB_STORE, cpp);
    }

    public static SQLLDAPStoreProvider getMysql(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
        return new SQLLDAPStoreProvider(node, OA4MPConfigTags.MYSQL_STORE, cpp);
    }

    public static SQLLDAPStoreProvider getPG(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
        return new SQLLDAPStoreProvider(node, OA4MPConfigTags.POSTGRESQL_STORE, cpp);
    }

    public static class SQLLDAPStoreProvider extends SQLStoreProvider<LDAPSQLStore> implements OA4MPConfigTags {
        public SQLLDAPStoreProvider(ConfigurationNode config,
                                    String type,
                                    ConnectionPoolProvider<? extends ConnectionPool> cpp) {
            super(config, cpp, type, LDAP_STORE, LDAPSQLStore.DEFAULT_TABLENAME, getConverter());
        }

        @Override
        public LDAPSQLStore newInstance(Table table) {
            return new LDAPSQLStore(getConnectionPool(), table, getLdapEntryProvider(), getConverter());

        }

        @Override
        public LDAPSQLStore get() {
            return newInstance(new LDAPStoreTable(getKeys(), getSchema(), getPrefix(), getTablename()));

        }
    }
}
