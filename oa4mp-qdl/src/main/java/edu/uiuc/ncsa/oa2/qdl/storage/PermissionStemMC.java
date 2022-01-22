package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionKeys;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import static edu.uiuc.ncsa.security.core.util.BasicIdentifier.newID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  7:08 AM
 */
public class PermissionStemMC<V extends Permission> extends StemConverter<V> {
    public PermissionStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    protected PermissionKeys kk() {
        return (PermissionKeys) keys;
    }

    /*
    7 attributes
    String adminID = "admin_id";
    String clientID = "client_id";
    String readable = "can_read";
    String writable = "can_write";
    String canCreate = "can_create";
    String canRemove = "can_remove";
    String canApprove = "can_approve";
     */
    @Override
    public V fromMap(StemVariable stem, V v) {
        v = super.fromMap(stem, v);
        if(isStringKeyOK(stem, kk().adminID())){
            v.setAdminID(newID(stem.getString(kk().adminID())));
        }
        if(isStringKeyOK(stem, kk().clientID())){
            v.setClientID(newID(stem.getString(kk().clientID())));
        }
        if(stem.containsKey(kk().readable())){
            v.setRead(stem.getBoolean(kk().readable()));
        }
        if(stem.containsKey(kk().writeable())){
            v.setWrite(stem.getBoolean(kk().writeable()));
        }
        if(stem.containsKey(kk().canRemove())){
            v.setDelete(stem.getBoolean(kk().canRemove()));
        }
        // 5
        if(stem.containsKey(kk().canCreate())){
            v.setCreate(stem.getBoolean(kk().canCreate()));
        }
        if(stem.containsKey(kk().canApprove())){
            v.setApprove(stem.getBoolean(kk().canApprove()));
        }
        // 7 attributes
        return v;
    }
    /*
        String adminID = "admin_id";
    String clientID = "client_id";
    String readable = "can_read";
    String writable = "can_write";
    String canCreate = "can_create";
    String canRemove = "can_remove";
    String canApprove = "can_approve";
     */

    @Override
    public StemVariable toMap(V v, StemVariable stem) {
        stem = super.toMap(v, stem);
        if (v.getAdminID() != null) {
            stem.put(kk().adminID(), v.getAdminID().toString());
        }
        if (v.getClientID() != null) {
            stem.put(kk().clientID(), v.getClientID().toString());
        }
        stem.put(kk().canApprove(), v.isApprove());
        stem.put(kk().canCreate(), v.isCreate());
        stem.put(kk().canRemove(), v.isDelete());
        // 5
        stem.put(kk().readable(), v.isRead());
        stem.put(kk().writeable(), v.isWrite());
        // 7 attributes
        return stem;
    }
}
