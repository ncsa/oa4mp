package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.inject.Provider;
import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  3:11 PM
 */
public class DSFSClientStoreProvider extends FSProvider<DSFSClientStore> implements OA4MPConfigTags {

    public DSFSClientStoreProvider(ConfigurationNode config,
                                   MapConverter<Client> cp,
                                   Provider<? extends Client> clientProvider) {
        super(config, FILE_STORE, CLIENTS_STORE, cp);
        this.clientProvider = clientProvider;
    }

    Provider<? extends Client> clientProvider;

    @Override
    protected DSFSClientStore produce(File dataPath, File indexPath) {
        DebugUtil.dbg(this, "dataPath=" + dataPath + ", indexPath=" + indexPath);
        DSFSClientStore store = new DSFSClientStore(dataPath, indexPath, (IdentifiableProviderImpl<Client>) clientProvider, converter);
        DebugUtil.dbg(this, "client name is " + store.getClass().getSimpleName());
        DebugUtil.dbg(this, "client store is a " + store);
        if (store.size() == 0) {
            System.err.println("NO ENTRIES IN CLIENT STORE");
        } else {
            System.err.println("Store contains " + store.size() + " entries.");
        }
      /*  System.err.println("printing identifiers...");

        for (Identifier x : store.keySet()) {
            System.err.println(x);
            System.err.println(store.get(x));
        }
        System.err.println("done!");*/

        return store;
    }
}
