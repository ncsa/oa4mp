package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.MultiDSTransactionStoreProvider;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  1:32 PM
 */
public class OA2MultiTypeProvider extends MultiDSTransactionStoreProvider {
    public OA2MultiTypeProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, IdentifiableProvider tp) {
        super(config, disableDefaultStore, logger, tp);
    }

    public OA2MultiTypeProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target, IdentifiableProvider tp) {
        super(config, disableDefaultStore, logger, type, target, tp);
    }

    @Override
    public TransactionStore getDefaultStore() {
        if(disableDefaultStore){
            throw new GeneralException("Error: default stores for this configuration have been disabled and none has been specified. Aborting...");
        }
        return new OA2MTStore(transactionProvider);
    }
}
