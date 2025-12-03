package org.oa4mp.delegation.server.storage.impl;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredMultiTypeProvider;
import org.oa4mp.delegation.server.storage.ClientStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  10:02 AM
 */
public  abstract class ClientStoreProvider<T extends ClientStore> extends MonitoredMultiTypeProvider<T> {

    public ClientStoreProvider(CFNode config,
                               boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }
}
