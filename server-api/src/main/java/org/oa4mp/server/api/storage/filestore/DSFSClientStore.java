package org.oa4mp.server.api.storage.filestore;

import org.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.impl.FSClientStore;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  10:47 AM
 */
public class DSFSClientStore extends FSClientStore<Client> {
    public DSFSClientStore(File f,
                           IdentifiableProviderImpl<Client> idp,
                           MapConverter<Client> cp,
                           boolean removeEmptyFiles,
                           boolean removeFailedFiles) {
        super(f, idp, cp, removeEmptyFiles,removeFailedFiles);
    }

    public DSFSClientStore(File storeDirectory,
                           File indexDirectory,
                           IdentifiableProviderImpl<Client> idp,
                           MapConverter<Client> cp,
                           boolean removeEmptyFiles,
                           boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, idp, cp, removeEmptyFiles,removeFailedFiles);
    }

    @Override
    public List<Client> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }

}
