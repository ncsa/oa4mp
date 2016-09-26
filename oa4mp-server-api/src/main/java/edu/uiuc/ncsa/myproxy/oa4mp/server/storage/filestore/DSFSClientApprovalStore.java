package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.FSClientApprovalStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  10:48 AM
 */
public class DSFSClientApprovalStore extends FSClientApprovalStore<ClientApproval> {
    public DSFSClientApprovalStore(File file,
                                   IdentifiableProviderImpl<ClientApproval> idp,
                                   MapConverter<ClientApproval> cp) {
        super(file, idp, cp);
    }

    public DSFSClientApprovalStore(File storeDirectory,
                                   File indexDirectory,
                                   IdentifiableProviderImpl<ClientApproval> idp,
                                   MapConverter<ClientApproval> cp) {
        super(storeDirectory, indexDirectory, idp, cp);
    }

}
