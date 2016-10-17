package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/11/16 at  1:58 PM
 */
public class PermissionConverter<V extends Permission> extends MapConverter<V> {
    public PermissionConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected PermissionKeys pk(){
        return (PermissionKeys) keys;
    }
    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value =  super.fromMap(map, v);
        value.setAdminID(map.getIdentifier(pk().adminID));
        value.setClientID(map.getIdentifier(pk().clientID));
        value.setApprove(map.getBoolean(pk().canApprove()));
        value.setCreate(map.getBoolean(pk().canCreate()));
        value.setDelete(map.getBoolean(pk().canRemove()));
        value.setRead(map.getBoolean(pk().readable()));
        value.setWrite(map.getBoolean(pk().writeable()));
        return value;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        data.put(pk().adminID(), value.getAdminID());
        data.put(pk().clientID(), value.getClientID());
        data.put(pk().canApprove(), value.isApprove());
        data.put(pk().canRemove(), value.isDelete());
        data.put(pk().writeable(), value.isWrite());
        data.put(pk().readable(), value.isRead());
        data.put(pk().canCreate(), value.isCreate());
    }
}
