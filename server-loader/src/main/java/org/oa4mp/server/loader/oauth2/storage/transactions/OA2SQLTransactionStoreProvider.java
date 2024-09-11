package org.oa4mp.server.loader.oauth2.storage.transactions;

import org.oa4mp.server.api.storage.MultiDSClientStoreProvider;
import org.oa4mp.server.api.admin.transactions.DSSQLTransactionStore;
import org.oa4mp.server.api.admin.transactions.DSSQLTransactionStoreProvider;
import org.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/4/14 at  4:08 PM
 */
public class OA2SQLTransactionStoreProvider<T extends DSSQLTransactionStore> extends DSSQLTransactionStoreProvider<T> {
    public OA2SQLTransactionStoreProvider(ConfigurationNode config,
                                          ConnectionPoolProvider<? extends ConnectionPool> cpp,
                                          String type,
                                          MultiDSClientStoreProvider clientStoreProvider,
                                          Provider<? extends OA2ServiceTransaction> tp,
                                          Provider<TokenForge> tfp,
                                          MapConverter converter) {
        super(config, cpp, type, clientStoreProvider, tp, tfp, converter);
    }

    @Override
    public T get() {
               return newInstance(new OA2TransactionTable((OA2TransactionKeys)converter.keys, getSchema(), getPrefix(), getTablename()));
    }

    @Override
    public T newInstance(Table table) {
        return (T) new OA2SQLTStore(tokenForgeProvider.get(),
                        getConnectionPool(),
                        table,
                        transactionProvider, converter);
    }
}
