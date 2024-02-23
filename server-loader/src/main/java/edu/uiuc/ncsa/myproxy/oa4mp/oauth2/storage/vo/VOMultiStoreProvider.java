package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMultiTypeProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/17/20 at  10:02 AM
 */
public class VOMultiStoreProvider<T extends VOStore<? extends VirtualOrganization>> extends MonitoredMultiTypeProvider<T> {
    public VOMultiStoreProvider(ConfigurationNode config,
                                boolean disableDefaultStore,
                                MyLoggingFacade logger,
                                String type,
                                String target,
                                VOProvider voProvider,
                                VOConverter voConverter) {
        super(config, disableDefaultStore, logger, type, target);
        this.voConverter = voConverter;
        this.voProvider = voProvider;
    }

    VOProvider voProvider = null;
    VOConverter voConverter = null;

    @Override
    public T getDefaultStore() {
        if (disableDefaultStore) {
            throw new GeneralException("Error: default stores for this configuration have been disabled and none has been specified. Aborting...");
        }
        return (T) new VOMemoryStore(voProvider, voConverter);
    }
}
