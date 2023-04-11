package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  2:50 PM
 */
public class MultiDSAdminClientStoreProvider<V extends AdminClient> extends MultiTypeProvider<AdminClientStore<V>> {
    public MultiDSAdminClientStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target,
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
