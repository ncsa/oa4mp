package org.oa4mp.server.loader.oauth2.storage.vi;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMultiTypeProvider;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/17/20 at  10:02 AM
 */
public class VIMultiStoreProvider<T extends VIStore<? extends VirtualIssuer>> extends MonitoredMultiTypeProvider<T> {
    public VIMultiStoreProvider(ConfigurationNode config,
                                boolean disableDefaultStore,
                                MyLoggingFacade logger,
                                String type,
                                String target,
                                VIProvider VIProvider,
                                VIConverter VIConverter) {
        super(config, disableDefaultStore, logger, type, target);
        this.VIConverter = VIConverter;
        this.VIProvider = VIProvider;
    }

    public VIMultiStoreProvider(CFNode config,
                                boolean disableDefaultStore,
                                MyLoggingFacade logger,
                                String type,
                                String target,
                                VIProvider VIProvider,
                                VIConverter VIConverter) {
        super(config, disableDefaultStore, logger, type, target);
        this.VIConverter = VIConverter;
        this.VIProvider = VIProvider;
    }

    VIProvider VIProvider = null;
    VIConverter VIConverter = null;

    @Override
    public T getDefaultStore() {
        if (disableDefaultStore) {
            throw new GeneralException("Error: default stores for this configuration have been disabled and none has been specified. Aborting...");
        }
        return (T) new VIMemoryStore(VIProvider, VIConverter);
    }
}
