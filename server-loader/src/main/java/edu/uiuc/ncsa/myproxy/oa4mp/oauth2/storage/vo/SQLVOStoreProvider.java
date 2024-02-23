package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  11:27 AM
 */
public class SQLVOStoreProvider<T extends SQLVOStore> extends SQLStoreProvider<T> implements OA4MPConfigTags {
    public static final String DEFAULT_TABLENAME = "virtual_organizations";

    public SQLVOStoreProvider(ConfigurationNode config,
                              ConnectionPoolProvider<? extends ConnectionPool> cpp,
                              String type,
                              VOConverter converter,
                              VOProvider VOProvider) {
        super(config, cpp, type, OA4MPConfigTags.VIRTUAL_ORGANIZATION_STORE,DEFAULT_TABLENAME , converter);
         this.VOProvider = VOProvider;
    }
    VOProvider VOProvider = null;

    @Override
    public T newInstance(Table table) {
        T t = (T) new SQLVOStore(getConnectionPool(),
                (VOTable) table,
                VOProvider, (VOConverter) converter);
        t.setUpkeepConfiguration(getUpkeepConfiguration());
        return t;
    }

    @Override
    public T get() {
        return newInstance(new VOTable((VOSerializationKeys)converter.keys,getSchema(),getPrefix(), getTablename()));
    }
}
