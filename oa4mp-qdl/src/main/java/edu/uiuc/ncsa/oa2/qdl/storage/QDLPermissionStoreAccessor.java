package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.Identifier;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  7:57 AM
 */
public class QDLPermissionStoreAccessor extends QDLStoreAccessor {
    public QDLPermissionStoreAccessor(String accessorType, PermissionsStore store) {
        super(accessorType, store);
    }
    protected PermissionsStore getPStore(){return ((PermissionsStore)store);}
    public List<Identifier> getClients(Identifier adminID){
        return getPStore().getClients(adminID);
    }
    public List<Identifier> getAdmins(Identifier clientID){
        return getPStore().getAdmins(clientID);
    }
    public int getClientCount(Identifier adminID){
        return getPStore().getClientCount(adminID);
    }
}
