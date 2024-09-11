package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import org.oa4mp.delegation.common.storage.clients.BaseClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/16 at  1:19 PM
 */
public interface BaseClientStore<V extends BaseClient> extends Store<V> {

    /**
     * Retrieve all clients of a given type from the approval store for the given status.
     *
     * @return
     */
    List<Identifier> getByStatus(String status, ClientApprovalStore clientApprovalStore);

    List<Identifier> getByApprover(String approver, ClientApprovalStore clientApprovalStore);

    /**
     * Process unused clients. This returns the total number of clients found that have
     * not access time and the number that satisfy the expiration
     */
    // Fixes https://github.com/ncsa/oa4mp/issues/80 and https://github.com/ncsa/oa4mp/issues/93
 //   UUCResponse unusedClientCleanup(UUCConfiguration uucConfiguration);
}
/*
 */