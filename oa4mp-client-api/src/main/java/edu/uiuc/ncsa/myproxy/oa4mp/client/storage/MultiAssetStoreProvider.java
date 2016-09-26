package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/31/13 at  1:20 PM
 */
public class MultiAssetStoreProvider extends MultiTypeProvider<AssetStore> {

    public MultiAssetStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger) {
        super(config, disableDefaultStore, logger, null, null);
    }

    AssetStore memoryStore = null;

    @Override
    public AssetStore getDefaultStore() {
        if (memoryStore == null) {
            logger.info("NO default asset store.");
            memoryStore = new MemoryAssetStore(new AssetProvider());
        }
        return memoryStore;
    }
}
