package org.oa4mp.server.api.storage;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import org.oa4mp.server.api.ClientApprovalProvider;
import org.oa4mp.server.api.util.ClientApprovalMemoryStore;
import org.oa4mp.server.api.util.ClientApproverConverter;
import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  4:07 PM
 */
public class MultiDSClientApprovalStoreProvider<V extends ClientApproval> extends MultiTypeProvider<ClientApprovalStore<V>> {

    public MultiDSClientApprovalStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger) {
        this(config, disableDefaultStore, logger, null, null);
    }
    public MultiDSClientApprovalStoreProvider(CFNode config, boolean disableDefaultStore, MyLoggingFacade logger) {
        this(config, disableDefaultStore, logger, null, null);
    }

    public MultiDSClientApprovalStoreProvider(ConfigurationNode config,
                                              boolean disableDefaultStore,
                                              MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }
    public MultiDSClientApprovalStoreProvider(CFNode config,
                                              boolean disableDefaultStore,
                                              MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }

    @Override
    public ClientApprovalStore getDefaultStore() {
        logger.info("using default in-memory client approval store.");
        ClientApprovalProvider caProvider = new ClientApprovalProvider();
        ClientApproverConverter cap = new ClientApproverConverter(caProvider);
        return  new ClientApprovalMemoryStore<ClientApproval>(caProvider, cap);
    }

}
