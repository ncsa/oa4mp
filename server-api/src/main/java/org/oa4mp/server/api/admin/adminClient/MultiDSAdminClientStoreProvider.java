package org.oa4mp.server.api.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMultiTypeProvider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  2:50 PM
 */
public class MultiDSAdminClientStoreProvider<V extends AdminClient> extends MonitoredMultiTypeProvider<AdminClientStore<V>> {

    public MultiDSAdminClientStoreProvider(CFNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target,
                                           IdentifiableProvider<V> app) {
        super(config, disableDefaultStore, logger, type, target);
        this.acp = app;
    }

    IdentifiableProvider<V> acp;

    @Override
    public AdminClientStore<V> getDefaultStore() {
        logger.info("Using default in memory admin client store.");
        return new AdminClientMemoryStore<>(acp);
    }
}
