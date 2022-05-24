package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionKeys;
import edu.uiuc.ncsa.qdl.variables.QDLList;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.ArrayList;
import java.util.List;

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
    9 attributes
    String adminID = "admin_id";
    String clientID = "client_id";
    String ersatzID = "ersatzID";
    String substitute = "substitute";
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
        if(stem.containsKey(kk().ersatzID())){
            List<Identifier> ids = new ArrayList<>();
            Object obj = stem.get(kk().ersatzID());
            // Should be a QDL list of identifiers
            if(obj instanceof StemVariable){
                QDLList list = ((StemVariable)obj).getQDLList();
                for(Object element : list){
                    if(element instanceof String){
                        ids.add(BasicIdentifier.newID((String)element));

                    }
                }
            }
            v.setErsatzChain(ids);
        }

        if(stem.containsKey(kk().readable())){
            v.setRead(stem.getBoolean(kk().readable()));
        }
        if(stem.containsKey(kk().writeable())){
            v.setWrite(stem.getBoolean(kk().writeable()));
        }
        if(stem.containsKey(kk().substitute())){
            v.setSubstitute(stem.getBoolean(kk().substitute()));
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
    String ersatzID = "ersatzID";
    String substitute = "substitute";
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
        if (v.getErsatzChain() != null && !v.getErsatzChain().isEmpty()) {
            List<Identifier> ids = v.getErsatzChain();
            QDLList list = new QDLList();
            // have to convert each to a string
            for(Identifier id : ids){
                list.add(id.toString());
            }
            StemVariable e = new StemVariable();
            e.setQDLList(list);
            stem.put(kk().ersatzID(), list);
        }

        stem.put(kk().substitute(), v.canSubstitute());
        stem.put(kk().canApprove(), v.isApprove());
        stem.put(kk().canCreate(), v.isCreate());
        stem.put(kk().canRemove(), v.isDelete());
        // 7
        stem.put(kk().readable(), v.isRead());
        stem.put(kk().writeable(), v.isWrite());
        // 8 attributes
        return stem;
    }
}
