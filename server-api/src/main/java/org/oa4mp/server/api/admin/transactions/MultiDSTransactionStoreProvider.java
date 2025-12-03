package org.oa4mp.server.api.admin.transactions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.transactions.TransactionMemoryStore;
import org.oa4mp.delegation.common.storage.transactions.TransactionStoreProvider;
import org.oa4mp.server.api.OA4MPServiceTransaction;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  3:54 PM
 */
public class MultiDSTransactionStoreProvider<V extends OA4MPServiceTransaction> extends TransactionStoreProvider<TransactionStore<V>> {

    public MultiDSTransactionStoreProvider(CFNode config,
                                           boolean disableDefaultStore,
                                           MyLoggingFacade logger,
                                           String type,
                                           String target,
                                           IdentifiableProvider<V> tp) {
        super(config,disableDefaultStore, logger, type, target);
        transactionProvider = tp;
    }
    protected IdentifiableProvider<V> transactionProvider;
    public MultiDSTransactionStoreProvider(CFNode  config, boolean disableDefaultStore,MyLoggingFacade logger, IdentifiableProvider<V> tp) {
        this(config, disableDefaultStore, logger, null, null, tp);
    }


    @Override
    public TransactionStore<V> getDefaultStore() {
        logger.info("Using default in memory transaction store.");
        return new TransactionMemoryStore<V>(transactionProvider);
    }
}
