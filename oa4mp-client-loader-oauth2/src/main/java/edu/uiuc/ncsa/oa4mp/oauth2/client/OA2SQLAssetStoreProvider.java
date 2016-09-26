package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  2:54 PM
 */
public class OA2SQLAssetStoreProvider extends SQLAssetStoreProvider {
    public OA2SQLAssetStoreProvider(ConfigurationNode config, String storeType, ConnectionPoolProvider<? extends ConnectionPool> cpp, AssetProvider assetProvider, MapConverter converter) {
        super(config, storeType, cpp, assetProvider, converter);
    }

    @Override
    public SQLAssetStore get() {
          return newInstance(new OA2AssetStoreTable(
                        (AssetSerializationKeys)converter.keys, getSchema(),
                        getPrefix(),
                        getTablename() == null ? AssetStoreTable.DEFAULT_TABLENAME : getTablename()));

    }
}
