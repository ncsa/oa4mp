package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/31/13 at  12:26 PM
 */
public class SQLAssetStoreProvider extends SQLStoreProvider<AssetStore> {
    public SQLAssetStoreProvider(ConfigurationNode config,
                                 String storeType,
                                 ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                 AssetProvider assetProvider,
                                 MapConverter converter
    ) {
        super(config, cpp, storeType, ClientXMLTags.ASSET_STORE, converter);
        this.assetProvider = assetProvider;
    }


    AssetProvider assetProvider;


    @Override
    public SQLAssetStore newInstance(Table table) {
        return new SQLAssetStore(getConnectionPool(),
                table,
                assetProvider,
                converter);
    }

    @Override
    public SQLAssetStore get() {
        return newInstance(new AssetStoreTable(
                (AssetSerializationKeys)converter.keys, getSchema(),
                getPrefix(),
                getTablename() == null ? AssetStoreTable.DEFAULT_TABLENAME : getTablename()));
    }
}
