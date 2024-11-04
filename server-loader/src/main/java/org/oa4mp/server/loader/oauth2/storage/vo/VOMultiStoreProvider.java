package org.oa4mp.server.loader.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMultiTypeProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/17/20 at  10:02 AM
 */
public class VOMultiStoreProvider<T extends VIStore<? extends VirtualIssuer>> extends MonitoredMultiTypeProvider<T> {
    public VOMultiStoreProvider(ConfigurationNode config,
                                boolean disableDefaultStore,
                                MyLoggingFacade logger,
                                String type,
                                String target,
                                VOProvider voProvider,
                                VIConverter VIConverter) {
        super(config, disableDefaultStore, logger, type, target);
        this.VIConverter = VIConverter;
        this.voProvider = voProvider;
    }

    VOProvider voProvider = null;
    VIConverter VIConverter = null;

    @Override
    public T getDefaultStore() {
        if (disableDefaultStore) {
            throw new GeneralException("Error: default stores for this configuration have been disabled and none has been specified. Aborting...");
        }
        return (T) new VIMemoryStore(voProvider, VIConverter);
    }
}
