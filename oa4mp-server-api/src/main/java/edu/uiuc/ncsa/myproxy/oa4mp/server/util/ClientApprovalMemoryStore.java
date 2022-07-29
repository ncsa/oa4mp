package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.MemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/2/18 at  2:01 PM
 */
public class ClientApprovalMemoryStore<V extends ClientApproval> extends MemoryStore<V> implements ClientApprovalStore<V> {

    MapConverter converter;

    public ClientApprovalMemoryStore(IdentifiableProviderImpl<V> vIdentifiableProvider, ClientApproverConverter converter) {
        super(vIdentifiableProvider);
        this.converter = converter;
    }

    @Override
    public boolean isApproved(Identifier identifier) {
        ClientApproval ca = get(identifier);
        if (ca == null) {
            return false;
        }
        return get(identifier).isApproved();
    }

    @Override
    public int getUnapprovedCount() {
        int count = 0;
        for (Identifier key : keySet()) {
            if (isApproved(key)) {
                count++;
            }
        }
        return count;
    }

    @Override
    public int getPendingCount() {
        int count = 0;
        for (Identifier key : keySet()) {
            ClientApproval approval = get(key);
            if (approval.getStatus() == ClientApproval.Status.PENDING)
                count++;
        }
        return count;
    }

    @Override
    public XMLConverter<V> getXMLConverter() {
        return converter;
    }

    @Override
    public MapConverter getMapConverter() {
        return converter;
    }

    @Override
    public List<Identifier> statusSearch(String status) {
        List<Identifier> identifiers = new ArrayList<>();
        for(Identifier identifier : keySet()){
            if(get(identifier).getStatus().getStatus().equals(status)){
                identifiers.add(identifier);
            }
        }
        return identifiers;
    }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return GenericStoreUtils.getMostRecent(this, n, attributes);
    }
}
