package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;
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
    }
}
