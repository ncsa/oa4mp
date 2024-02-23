package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCResponse;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.storage.AggregateStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/24/12 at  11:18 AM
 */
public class AggregateClientStore<V extends ClientStore> extends AggregateStore<V> implements ClientStore {
    public AggregateClientStore(V... stores) {
        super(stores);
    }

    @Override
    public XMLConverter getXMLConverter() {
        throw new NotImplementedException("Error: No single converter for an aggregate store is possible");
    }

    @Override
    public MapConverter getMapConverter() {
        throw new NotImplementedException("Error: No single converter for an aggregate store is possible");
    }

    @Override
    public List<Identifier> getByStatus(String status, ClientApprovalStore clientApprovalStore) {
        throw new NotImplementedException("Error: No single converter for an aggregate store is possible");
    }

    @Override
    public List<Identifier> getByApprover(String approver, ClientApprovalStore clientApprovalStore) {
        throw new NotImplementedException("Error: No single converter for an aggregate store is possible");
    }


}
