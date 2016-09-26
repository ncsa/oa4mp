package edu.uiuc.ncsa.myproxy.oa4mp.server.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientMemoryStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientStoreProvider;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  2:27 PM
 */
public class MultiDSClientStoreProvider<V extends Client> extends ClientStoreProvider<ClientStore<V>> {

    public MultiDSClientStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger) {
        this(config,disableDefaultStore, logger, null, null, null);
    }
    public MultiDSClientStoreProvider(ConfigurationNode config,
                                      boolean disableDefaultStore,
                                      MyLoggingFacade logger,
                                      String type,
                                      String target,
                                      IdentifiableProvider<? extends Client> clientProvider) {
        super(config, disableDefaultStore, logger, type, target);
        this.clientProvider = clientProvider;
    }
    IdentifiableProvider<? extends Client> clientProvider;

    @Override
    public ClientStore<V> getDefaultStore() {
        logger.info("Using default in memory client store");
        return new ClientMemoryStore(clientProvider);
    }
}
