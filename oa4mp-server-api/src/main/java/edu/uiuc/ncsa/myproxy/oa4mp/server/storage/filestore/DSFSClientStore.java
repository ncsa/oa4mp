package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.FSClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  10:47 AM
 */
public class DSFSClientStore extends FSClientStore<Client> {
    public DSFSClientStore(File f,
                           IdentifiableProviderImpl<Client> idp,
                           MapConverter<Client> cp) {
        super(f, idp, cp);
    }

    public DSFSClientStore(File storeDirectory,
                           File indexDirectory,
                           IdentifiableProviderImpl<Client> idp,
                           MapConverter<Client> cp) {
        super(storeDirectory, indexDirectory, idp, cp);
    }

}
