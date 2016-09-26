package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSClientStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.keys.DSTransactionKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.DSSQLTransactionStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.DSTransactionTable;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;

import static edu.uiuc.ncsa.security.delegation.server.storage.SQLServiceTransactionStore.DEFAULT_TABLENAME;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/17/12 at  9:11 AM
 */
public class DSSQLTransactionStoreProvider<T extends DSSQLTransactionStore> extends SQLStoreProvider<T> implements OA4MPConfigTags {
    public DSSQLTransactionStoreProvider(
            ConfigurationNode config,
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
