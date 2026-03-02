package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

public class KEMultiStoreProvider<T extends KEStore<? extends KERecord>> extends MultiTypeProvider<T> {
    public KEMultiStoreProvider(CFNode config,
                                boolean disableDefaultStore,
                                MyLoggingFacade logger,
                                String type,
                                String target,
                                KERecordProvider keRecordProvider,
                                KEConverter<? extends KERecord> keConverter) {
        super(config, disableDefaultStore, logger, type, target);
        this.keRecordProvider = keRecordProvider;
        this.keConverter = keConverter;
    }
    KERecordProvider<? extends KERecord> keRecordProvider;
    KEConverter<? extends KERecord> keConverter;
    @Override
    public T getDefaultStore() {
        if (disableDefaultStore) {
            throw new GeneralException("Error: default stores for this configuration have been disabled and none has been specified. Aborting...");
        }
        return (T) new KEMemoryStore(keRecordProvider, keConverter);
    }

}
