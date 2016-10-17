package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.MemoryStore;

import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  4:18 PM
 */
public class MemoryPermissionStore<V extends Permission> extends MemoryStore<V> implements PermissionsStore<V> {
    HashMap<Identifier,List<Identifier>> adminMap = new HashMap(); // map for admin to client lookup.
    HashMap<Identifier,List<Identifier>> clientMap = new HashMap();

    public MemoryPermissionStore(IdentifiableProvider<V> identifiableProvider) {
        super(identifiableProvider);
    }

    @Override
    public List<Identifier> getAdmins(Identifier clientID) {
        return clientMap.get(clientID);
    }

    @Override
    public List<Identifier> getClients(Identifier adminID) {
        return adminMap.get(adminID);
    }

    @Override
    public Permission get(Identifier adminID, Identifier clientID) {
        List<Identifier> clients = getAdmins(adminID);
        for(Identifier id : clients){
            if(id.equals(clientID)){

            }
        }
          return null;
    }

    @Override
    public boolean hasEntry(Identifier adminID, Identifier clientID) {
        return get(adminID,clientID) != null;
    }

    @Override
    public V put(Identifier key, V value) {
        V p = (V)get(value.getAdminID(), value.getClientID());
        if(p == null){
        }else{
            // replace it
            remove(key);
        }

        return super.put(key, value);
    }
}
