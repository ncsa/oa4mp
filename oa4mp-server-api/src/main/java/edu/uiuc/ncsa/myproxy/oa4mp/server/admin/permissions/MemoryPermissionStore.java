package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.MemoryStore;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  4:18 PM
 */
public class MemoryPermissionStore<V extends Permission> extends MemoryStore<V> implements PermissionsStore<V> {
    public static class IDTriple {
        public IDTriple(Permission p) {
            pID = p.getIdentifier();
            adminID = p.getAdminID();
            clientID = p.getClientID();
        }

        Identifier pID;
        Identifier clientID;
        Identifier adminID;

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof IDTriple)) return false;
            IDTriple idTriple = (IDTriple) obj;
            if (!checkEquals(idTriple.clientID, clientID)) return false;
            if (!checkEquals(idTriple.adminID, adminID)) return false;
            if (!checkEquals(idTriple.pID, pID)) return false;
            return true;
        }

    }

    /**
     * The map of all admin ids. The key is an admin id, the values are lists of cilent, permission and admin triples.
     */
    HashMap<Identifier, List<IDTriple>> adminMap = new HashMap(); // map for admin to client lookup.
    /**
      * The map of all client ids. The key is a client id, the values are lists of cilent, permission and admin triples.
      */
    HashMap<Identifier, List<IDTriple>> clientMap = new HashMap();

    public MemoryPermissionStore(IdentifiableProvider<V> identifiableProvider) {
        super(identifiableProvider);
    }

    @Override
    public List<Identifier> getAdmins(Identifier clientID) {
        List<IDTriple> ids = clientMap.get(clientID);
        LinkedList<Identifier> admins = new LinkedList<>();
        if (ids == null) return admins;

        for (IDTriple idTriple : ids) {
            admins.add(idTriple.adminID);
        }
        return admins;
    }

    @Override
    public List<Identifier> getClients(Identifier adminID) {

        List<IDTriple> ids = adminMap.get(adminID);
        LinkedList<Identifier> clients = new LinkedList<>();
        if (ids == null) return clients;
        for (IDTriple idTriple : ids) {
            clients.add(idTriple.clientID);
        }
        return clients;

    }

    @Override
    public PermissionList get(Identifier adminID, Identifier clientID) {
        List<IDTriple> clients = adminMap.get(adminID);

        PermissionList permissions = new PermissionList();
        if (clients == null) return permissions;
        for (IDTriple id : clients) {
            if (id.clientID != null && id.clientID.equals(clientID)) {

                permissions.add(get(id.pID));
            }
        }
        return permissions;
    }

    @Override
    public boolean hasEntry(Identifier adminID, Identifier clientID) {
        return !get(adminID, clientID).isEmpty();
    }

    protected void addToClients(V p) {
        IDTriple idTriple = new IDTriple(p);
        List<IDTriple> clients = clientMap.get(p.getClientID());
        if (clients == null) {
            clients = new LinkedList<>();
            clientMap.put(p.getClientID(), clients);
        }
        if (!clientMap.containsValue(idTriple)) {
            clients.add(idTriple);
        }

    }

    protected void addToAdmins(V p) {
        IDTriple idTriple = new IDTriple(p);
        List<IDTriple> admins = adminMap.get(p.getAdminID());
        if (admins == null) {
            admins = new LinkedList<>();
            adminMap.put(p.getAdminID(), admins);
        }
        if (!adminMap.containsValue(idTriple)) {
            admins.add(idTriple);
        }

    }

    @Override
    public void clear() {
        adminMap = new HashMap();
        clientMap = new HashMap();
        super.clear();
    }

    protected void removeFromClients(V p){
        List<IDTriple> clients = clientMap.get(p.getClientID());
        if(clients == null) return;
        for(IDTriple triple : clients){
            if(triple.pID.equals(p.getIdentifier())){
                clients.remove(triple);
            }
        }

    }

    /**
     * Part of the contract for this store is that saving a permission with an updated ID (AC or client)
     * should remove the old value, which means we have to clean out stale entries from the clientMpa
     * and adminMap. The problem with a memory store is that the permission
     * @param p
     */
    protected void removeFromAdmins(V p){
        List<IDTriple> admins = adminMap.get(p.getAdminID());
            if(admins == null) return;
            for(IDTriple triple : admins){
                if(triple.pID.equals(p.getIdentifier())){
                    admins.remove(triple);
                }
            }
    }

    @Override
    public V put(Identifier key, V value2) {
        // Do NOT store the permission when it comes in, Make a clone so if the user
        // updates it (e.g. changes the admin client id) we can find all the references to it.
        // If you store the actual permission sent, then they can change its state without using the
        // store interface and you cannot track who has permissions to what.

        V value = (V) value2.clone();
        if(containsKey(key)){
            // remove the current value (in case, say, the admin client ID changes) because otherwise you
            // will get orphans in the admin and client maps.
            V p = get (key);
            removeFromAdmins(p);
            removeFromClients(p);
            remove(key);
        }
        List<Permission> p = get(value.getAdminID(), value.getClientID());
        if (p.isEmpty()) {
            addToAdmins(value);
            addToClients(value);
            return super.put(key, value);

        }
        // there are permission(s) corresponding to this pair of client, admin id.
        // make sure we don't already have it
        for (Permission tempP : p) {
            if (tempP.getIdentifier().equals(value.getIdentifier())) {
                // the identifier is there.
                remove(key);
                adminMap.remove(value.getAdminID());
                clientMap.remove(value.getClientID());
            }
        }
        addToAdmins(value);
        addToClients(value);
        return super.put(key, value);
    }

    @Override
    public V remove(Object key) {
        if(containsKey(key)){
            V p = get(key);
         removeFromAdmins(p);
         removeFromClients(p);

        }
        return super.remove(key);
    }
}
