package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/9/12 at  4:47 PM
 */
public interface ClientApprovalStore<V extends ClientApproval> extends Store<V> {
    /**
     * Returns true if the client with the given identifier has been approved, false otherwise.
     * Not that this returns false even in the case that there is no such client.
     * @param identifier
     * @return
     */
    boolean isApproved(Identifier identifier);

    /**
     * Get the number of approvals that are as yet unapproved.
     * @return
     */
    int getUnapprovedCount();
    int getPendingCount();
    MapConverter getMapConverter();
    List<Identifier> statusSearch(String status);
}
