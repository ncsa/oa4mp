package org.oa4mp.server.qdl.storage;

import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  7:57 AM
 */
public class QDLPermissionStoreAccessor extends QDLStoreAccessor {
    public QDLPermissionStoreAccessor(String accessorType, PermissionsStore store, MyLoggingFacade facade) {
        super(accessorType, store, facade);
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
