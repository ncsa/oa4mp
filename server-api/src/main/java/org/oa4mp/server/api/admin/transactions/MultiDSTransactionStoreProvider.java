package org.oa4mp.server.api.admin.transactions;

import org.oa4mp.server.api.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.transactions.TransactionMemoryStore;
import org.oa4mp.delegation.common.storage.transactions.TransactionStoreProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  3:54 PM
 */
public class MultiDSTransactionStoreProvider<V extends OA4MPServiceTransaction> extends TransactionStoreProvider<TransactionStore<V>> {
    public MultiDSTransactionStoreProvider(ConfigurationNode config,
                                           boolean disableDefaultStore,
                                           MyLoggingFacade logger,
                                           String type,
                                           String target,
                                           IdentifiableProvider<V> tp) {
        super(config,disableDefaultStore, logger, type, target);
        transactionProvider = tp;
    }
    protected IdentifiableProvider<V> transactionProvider;
    public MultiDSTransactionStoreProvider(ConfigurationNode config, boolean disableDefaultStore,MyLoggingFacade logger, IdentifiableProvider<V> tp) {
        // doesn't need to have target and type since this has to determine them,
        this(config, disableDefaultStore, logger, null, null, tp);
    }

    @Override
    public TransactionStore<V> getDefaultStore() {
        logger.info("Using default in memory transaction store.");
        return new TransactionMemoryStore<V>(transactionProvider);
    }
}
