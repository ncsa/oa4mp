package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
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
        return new DSFSClientStore(dataPath, indexPath, (IdentifiableProviderImpl<Client>) clientProvider,  converter);
    }
}
