package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.oa4mp.server.api.OA4MPConfigTags;

public class KESQLStoreProvider<T extends KESQLStore> extends SQLStoreProvider<T> implements OA4MPConfigTags {
    public KESQLStoreProvider(CFNode config,
                              ConnectionPoolProvider<? extends ConnectionPool> cpp,
                              String type,
                              KEConverter converter,
                              KERecordProvider<? extends KERecord> keRecordProvider) {
        super(config, cpp, type, KEY_STORE, DEFAULT_TABLENAME, converter);
        this.keRecordProvider = keRecordProvider;
    }
    public static final String DEFAULT_TABLENAME = "key_records";

    KERecordProvider<? extends KERecord> keRecordProvider;
    @Override
    public T newInstance(Table table) {
        return (T) new KESQLStore(getConnectionPool(), table, keRecordProvider, converter);
    }

    @Override
    public T get() {
        return newInstance(new KEStoreTable((KESerializationKeys)converter.keys,getSchema(),getPrefix(), getTablename()));
    }

}
