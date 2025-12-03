package org.oa4mp.server.loader.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.oa4mp.server.api.OA4MPConfigTags;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  11:27 AM
 */
public class SQLTXRStoreProvider<T extends SQLTXRecordStore> extends SQLStoreProvider<T> implements OA4MPConfigTags {
    public static final String DEFAULT_TABLENAME = "tx_records";

    public SQLTXRStoreProvider(CFNode config,
                               ConnectionPoolProvider<? extends ConnectionPool> cpp,
                               String type,
                               TXRecordConverter converter,
                               TXRecordProvider txRecordProvider) {
        super(config, cpp, type, OA4MPConfigTags.TOKEN_EXCHANGE_RECORD_STORE,DEFAULT_TABLENAME , converter);
        this.txRecordProvider = txRecordProvider;
    }
    TXRecordProvider txRecordProvider = null;

    @Override
    public T newInstance(Table table) {
        return (T) new SQLTXRecordStore(getConnectionPool(),
                (TXRecordTable) table,
                txRecordProvider, (TXRecordConverter) converter);
    }

    @Override
    public T get() {
        return newInstance(new TXRecordTable((TXRecordSerializationKeys)converter.keys,getSchema(),getPrefix(), getTablename()));
    }
}
