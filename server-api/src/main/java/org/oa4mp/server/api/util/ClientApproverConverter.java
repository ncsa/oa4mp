package org.oa4mp.server.api.util;

import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/12 at  11:10 AM
 */
public class ClientApproverConverter<V extends ClientApproval> extends MapConverter<V> {
    public ClientApproverConverter(IdentifiableProviderImpl<V> identifiableProvider) {
        super(new ClientApprovalKeys(), identifiableProvider);
    }

    public ClientApproverConverter(SerializationKeys keys, IdentifiableProviderImpl<V> identifiableProvider) {
        super(keys, identifiableProvider);
    }

    protected ClientApprovalKeys getCAKeys() {
        return (ClientApprovalKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V ca) {
        ca = super.fromMap(map, ca);
        ca.setApproved(map.getBoolean(getCAKeys().approved()));
        ca.setApprover(map.getString(getCAKeys().approver()));
        ca.setApprovalTimestamp(map.getDate(getCAKeys().approvalTS()));
        String status = map.getString(getCAKeys().status());
        if(status == null){
            ca.setStatus(ClientApproval.Status.NONE);
        }else {
            ClientApproval.Status status1 = ClientApproval.Status.resolveByStatusValue(status);
            ca.setStatus(status1);
        }
        return ca;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> map) {
        super.toMap(value, map);
        map.put(getCAKeys().approver(), value.getApprover());
        if (value.getApprovalTimestamp() == null) {
            value.setApprovalTimestamp(new java.util.Date());
        }
        map.put(getCAKeys().approvalTS(), value.getApprovalTimestamp());
        map.put(getCAKeys().approved(), value.isApproved());
        if(value.getStatus() == null){
            map.put(getCAKeys().status(), ClientApproval.Status.NONE);
        }else {
            map.put(getCAKeys().status(), value.getStatus().getStatus());
        }
    }
}
