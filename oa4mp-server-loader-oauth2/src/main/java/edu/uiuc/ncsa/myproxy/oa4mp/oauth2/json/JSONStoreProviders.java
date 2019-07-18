package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.core.configuration.provider.TypedProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;
import java.util.Date;

/**
 * This centralized (and simplifies) the creation of the various stores needed to support JSON. 
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  11:25 AM
 */
public class JSONStoreProviders {
    public static final String JSON_STORE_COMPONENT = "jsonStore";

    protected static IdentifiableProviderImpl<? extends JSONEntry> jsonEntryProvider;
    protected static JSONConverter<? extends JSONEntry> jsonConverter;
    protected static JSONStoreKeys jsonStoreKeys;

    public static class JSONMemoryStore<V extends JSONEntry> extends MemoryStore<V> implements JSONStore<V>{
        public JSONMemoryStore(IdentifiableProvider<V> identifiableProvider) {
            super(identifiableProvider);
        }

        JSONConverter jc = null;
        @Override
        public XMLConverter<V> getXMLConverter() {
            if(jc == null){
               jc = new JSONConverter(new JSONStoreKeys(), identifiableProvider);
            }
            return jc; // in case anyone needs to dump this store to a file.
        }

        @Override
        protected void realSave(V value) {
            value.setLastModified(new Date());
            super.realSave(value);
        }
    }

    public static IdentifiableProviderImpl<? extends JSONEntry> getJsonEntryProvider() {
        if (jsonEntryProvider == null) {
            jsonEntryProvider = new JSONEntryProvider<>(new OA4MPIdentifierProvider(JSON_STORE_COMPONENT));
        }
        return jsonEntryProvider;
    }
    public static JSONStoreKeys getJsonStoreKeys(){
        if(jsonStoreKeys == null){
                          jsonStoreKeys = new JSONStoreKeys();
        }
        return jsonStoreKeys;
    }
    public static JSONConverter<? extends JSONEntry> getJsonConverter(){
        if(jsonConverter == null){
                 jsonConverter = new JSONConverter<>(getJsonStoreKeys(),getJsonEntryProvider());;
        }
        return jsonConverter;
    }

    public static class JSONStoreFSProvider extends FSProvider<JSONFileStore> implements OA4MPConfigTags{
        public JSONStoreFSProvider(ConfigurationNode config) {
            super(config, FILE_STORE, JSON_STORE, getJsonConverter());
        }

        @Override
        protected JSONFileStore produce(File dataPath, File indexPath, boolean removeEmptyFiles) {
            return new JSONFileStore(dataPath,indexPath,getJsonEntryProvider(),getJsonConverter(), removeEmptyFiles);
        }
    }
    public static JSONStoreFSProvider getJSFSP(ConfigurationNode node){
        return new JSONStoreFSProvider(node);
    }

    public static JSONStoreMSProvider getJSMSP(ConfigurationNode node){return new JSONStoreMSProvider(node);}
    public static class JSONStoreMSProvider extends TypedProvider<JSONStore> implements OA4MPConfigTags{
        public JSONStoreMSProvider(ConfigurationNode config) {
            super(config, MEMORY_STORE, JSON_STORE);
        }

        @Override
        public Object componentFound(CfgEvent configurationEvent) {
            return null;
        }

        @Override
        public JSONStore get() {
            return new JSONMemoryStore(getJsonEntryProvider());
        }
    }
   public static class JSONStoreSQLStoreProvider  extends SQLStoreProvider<JSONSQLStore> implements OA4MPConfigTags{
       public JSONStoreSQLStoreProvider(ConfigurationNode node, String type, ConnectionPoolProvider<? extends ConnectionPool> cpp) {
           super(node, cpp, type, JSON_STORE_COMPONENT, JSONStoreSQLTable.DEFAULT_TABLE_NAME, getJsonConverter());
       }

       @Override
       public JSONSQLStore newInstance(Table table) {
           return new JSONSQLStore(getConnectionPool(),table,JSONStoreProviders::getJsonEntryProvider,getJsonConverter());
       }

       @Override
       public JSONSQLStore get() {
           return newInstance(new JSONStoreSQLTable(getJsonStoreKeys(),getSchema(),getPrefix(),getTablename()));
       }
   }
     public static JSONStoreSQLStoreProvider getMariaJS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp){
        return new JSONStoreSQLStoreProvider(node, OA4MPConfigTags.MARIADB_STORE, cpp);
     }

    public static JSONStoreSQLStoreProvider getMySQLJS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp){
       return new JSONStoreSQLStoreProvider(node, OA4MPConfigTags.MYSQL_STORE, cpp);
    }

    public static JSONStoreSQLStoreProvider getPostgresJS(ConfigurationNode node, ConnectionPoolProvider<? extends ConnectionPool> cpp){
         return new JSONStoreSQLStoreProvider(node, OA4MPConfigTags.POSTGRESQL_STORE, cpp);
      }
}
