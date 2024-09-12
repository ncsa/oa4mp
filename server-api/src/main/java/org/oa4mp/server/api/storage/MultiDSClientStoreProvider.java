package org.oa4mp.server.api.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.server.storage.impl.ClientMemoryStore;
import org.oa4mp.delegation.server.storage.impl.ClientStoreProvider;
import org.oa4mp.delegation.common.storage.clients.Client;
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
    protected IdentifiableProvider<? extends Client> clientProvider;

    @Override
    public ClientStore<V> getDefaultStore() {
        logger.info("Using default in memory client store");
        return new ClientMemoryStore(clientProvider);
    }
}
