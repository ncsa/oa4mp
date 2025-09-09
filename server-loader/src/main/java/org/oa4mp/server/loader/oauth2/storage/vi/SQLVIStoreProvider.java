package org.oa4mp.server.loader.oauth2.storage.vi;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import org.oa4mp.server.api.OA4MPConfigTags;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  11:27 AM
 */
public class SQLVIStoreProvider<T extends SQLVIStore> extends SQLStoreProvider<T> implements OA4MPConfigTags {
    public static final String DEFAULT_TABLENAME = "virtual_organizations";

    public SQLVIStoreProvider(ConfigurationNode config,
                              ConnectionPoolProvider<? extends ConnectionPool> cpp,
                              String type,
                              VIConverter converter,
                              VIProvider VIProvider) {
        super(config, cpp, type, OA4MPConfigTags.VIRTUAL_ORGANIZATION_STORE,DEFAULT_TABLENAME , converter);
         this.VIProvider = VIProvider;
    }

    public SQLVIStoreProvider(CFNode config,
                              ConnectionPoolProvider<? extends ConnectionPool> cpp,
                              String type,
                              VIConverter converter,
                              VIProvider VIProvider) {
        super(config, cpp, type, OA4MPConfigTags.VIRTUAL_ORGANIZATION_STORE,DEFAULT_TABLENAME , converter);
        this.VIProvider = VIProvider;
    }
    VIProvider VIProvider = null;

    @Override
    public T newInstance(Table table) {
        T t = (T) new SQLVIStore(getConnectionPool(),
                (VITable) table,
                VIProvider, (VIConverter) converter);
        t.setUpkeepConfiguration(getUpkeepConfiguration());
        return t;
    }

    @Override
    public T get() {
        return newInstance(new VITable((VISerializationKeys)converter.keys,getSchema(),getPrefix(), getTablename()));
    }
}
