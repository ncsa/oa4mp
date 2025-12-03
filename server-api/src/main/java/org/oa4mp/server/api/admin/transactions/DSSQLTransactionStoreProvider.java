package org.oa4mp.server.api.admin.transactions;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.OA4MPServiceTransaction;
import org.oa4mp.server.api.storage.MultiDSClientStoreProvider;

import javax.inject.Provider;

import static org.oa4mp.delegation.server.storage.SQLServiceTransactionStore.DEFAULT_TABLENAME;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/17/12 at  9:11 AM
 */
public class DSSQLTransactionStoreProvider<T extends DSSQLTransactionStore> extends SQLStoreProvider<T> implements OA4MPConfigTags {

    public DSSQLTransactionStoreProvider(
            CFNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            MultiDSClientStoreProvider clientStoreProvider,
            Provider<? extends OA4MPServiceTransaction> tp,
            Provider<TokenForge> tfp,
            MapConverter converter) {
        super(config, cpp,  type, OA4MPConfigTags.TRANSACTIONS_STORE, DEFAULT_TABLENAME, converter);
        this.clientStoreProvider = clientStoreProvider;
        this.transactionProvider = tp;
        tokenForgeProvider = tfp;
    }

    protected Provider<TokenForge> tokenForgeProvider;
    protected Provider<? extends OA4MPServiceTransaction> transactionProvider;
    protected MultiDSClientStoreProvider clientStoreProvider;

    @Override
    public T newInstance(Table table) {
        return (T) new DSSQLTransactionStore(tokenForgeProvider.get(),
                getConnectionPool(),
                table,
                transactionProvider, converter);
    }

    @Override
    public T get() {
        return newInstance(new DSTransactionTable((DSTransactionKeys)converter.keys, getSchema(), getPrefix(), getTablename()));
    }

}
