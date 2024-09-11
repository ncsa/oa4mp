package org.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/13/12 at  10:43 AM
 */
public abstract class TransactionStoreProvider<T extends TransactionStore<? extends BasicTransaction>> extends MultiTypeProvider<T> {
    public TransactionStoreProvider(ConfigurationNode config,
                                    boolean disableDefaultStore,MyLoggingFacade loggingFacade,
                                    String type, String target) {
        super(config, disableDefaultStore, loggingFacade, type, target);
    }


}
