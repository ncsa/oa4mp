package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json;

import edu.uiuc.ncsa.security.core.configuration.provider.MultiTypeProvider;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.json.JSONStore;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  10:37 AM
 */
public class MultiJSONStoreProvider extends MultiTypeProvider<JSONStore> {
    public MultiJSONStoreProvider() {
    }

    public MultiJSONStoreProvider(ConfigurationNode config, boolean disableDefaultStore, MyLoggingFacade logger, String type, String target) {
        super(config, disableDefaultStore, logger, type, target);
    }

    public MultiJSONStoreProvider(MyLoggingFacade logger, String type, String target) {
        super(logger, type, target);
    }

    @Override
    public JSONStore getDefaultStore() {
        return null;
    }
}
