package edu.uiuc.ncsa.myproxy.oa4mp.server.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientApprovalMemoryStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  4:07 PM
 */
public class MultiDSClientApprovalStoreProvider<V extends ClientApproval> extends MultiTypeProvider<ClientApprovalStore<V>> {

    public MultiDSClientApprovalStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger) {
        this(config, disableDefaultStore, logger, null, null);

    }

    public MultiDSClientApprovalStoreProvider(ConfigurationNode config,
                                              boolean disableDefaultStore,
                                              MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }

    @Override
    public ClientApprovalStore getDefaultStore() {
        logger.info("using default in-memory client approval store.");
        return  new ClientApprovalMemoryStore<ClientApproval>(new ClientApprovalProvider());
    }

}
