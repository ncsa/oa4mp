package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/17/20 at  10:02 AM
 */
public class TXMultiStoreProvider<T extends TXStore<? extends TXRecord>> extends MultiTypeProvider<T> {
    public TXMultiStoreProvider(ConfigurationNode config,
                                boolean disableDefaultStore,
                                MyLoggingFacade logger,
                                String type,
                                String target,
                                TXRecordProvider txRecordProvider,
                                TXRecordConverter txRecordConverter) {
        super(config, disableDefaultStore, logger, type, target);
        this.txRecordConverter = txRecordConverter;
        this.txRecordProvider = txRecordProvider;
    }

    TXRecordProvider txRecordProvider = null;
    TXRecordConverter txRecordConverter = null;

    @Override
    public T getDefaultStore() {
        if (disableDefaultStore) {
            throw new GeneralException("Error: default stores for this configuration have been disabled and none has been specified. Aborting...");
        }
        return (T) new TXMemoryStore(txRecordProvider, txRecordConverter);
    }
}
