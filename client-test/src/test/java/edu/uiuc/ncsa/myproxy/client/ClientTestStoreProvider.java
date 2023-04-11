package edu.uiuc.ncsa.myproxy.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  2:23 PM
 */
public abstract class ClientTestStoreProvider {
    protected ConfigurationNode node;

    public abstract ConfigurationLoader getConfigLoader();

    ClientEnvironment ce = null;

    public ClientEnvironment getCE() {
        if (ce == null) {
            ce = (ClientEnvironment) getConfigLoader().load();
        }
        return ce;
    }

    public AssetStore getAssetStore() {
        return getCE().getAssetStore();
    }

}
