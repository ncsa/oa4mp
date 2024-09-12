package org.oa4mp.server.api.storage.filestore;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.impl.FSClientApprovalStore;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  10:48 AM
 */
public class DSFSClientApprovalStore extends FSClientApprovalStore<ClientApproval> {
    public DSFSClientApprovalStore(File file,
                                   IdentifiableProviderImpl<ClientApproval> idp,
                                   MapConverter<ClientApproval> cp,
                                   boolean removeEmptyFiles,
                                   boolean removeFailedFiles) {
        super(file, idp, cp, removeEmptyFiles, removeFailedFiles);
    }

    public DSFSClientApprovalStore(File storeDirectory,
                                   File indexDirectory,
                                   IdentifiableProviderImpl<ClientApproval> idp,
                                   MapConverter<ClientApproval> cp,
                                   boolean removeEmptyFiles,
                                   boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, idp, cp, removeEmptyFiles, removeFailedFiles);
    }

    @Override
    public List<Identifier> statusSearch(String status) {
        ArrayList<Identifier> results = new ArrayList();
        Collection<ClientApproval> values = values();
        Iterator iterator = values.iterator();
        ClientApprovalKeys caKeys = (ClientApprovalKeys) getMapConverter().getKeys();
        String statusKey = caKeys.status();
        while (iterator.hasNext()) {
            ClientApproval v = (ClientApproval) iterator.next();
            if (v.getStatus().getStatus().equals(statusKey)) {
                results.add(v.getIdentifier());
            }
        }
        return results;
    }

    @Override
    public List<ClientApproval> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }
}
