package org.oa4mp.delegation.server.storage;


import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.storage.AggregateStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.List;

/**
 * An aggregate client approval store.
 * <p>Created by Jeff Gaynor<br>
 * on 5/24/12 at  11:14 AM
 */
public class AggregateCAStore<V extends ClientApprovalStore> extends AggregateStore<V> implements ClientApprovalStore {
    public AggregateCAStore(V... stores) {
        super(stores);
    }

    @Override
    public boolean isApproved(Identifier identifier) {
        for (ClientApprovalStore s : stores) {
            if (s.isApproved(identifier)) return true;
        }
        return false;
    }

    @Override
    public int getUnapprovedCount() {
        int count = 0;
        for (ClientApprovalStore s : stores) {
            count = count + s.getUnapprovedCount();
        }
        return count;
    }

    @Override
    public int getPendingCount() {
        int count = 0;
        for (ClientApprovalStore s : stores) {
            count = count + s.getPendingCount();
        }
        return count;
    }

    @Override
    public XMLConverter getXMLConverter() {
        throw new NotImplementedException("Error: Cannot have a single converter for an aggregate store.");
    }

    @Override
    public MapConverter getMapConverter() {
        throw new NotImplementedException("Error: Cannot have a single converter for an aggregate store.");
    }

    @Override
    public List<Identifier> statusSearch(String status) {
        throw new NotImplementedException();
    }
}
