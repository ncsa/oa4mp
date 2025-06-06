package org.oa4mp.server.api.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;

/**
 * Generic utilities for a permission store.
 * <p>Created by Jeff Gaynor<br>
 * on 5/21/22 at  6:56 AM
 */
public class PermissionStoreUtil {
    /**
     * returns the chain or a null if there is no such chain.
     *
     * @param permissionsStore
     * @param adminID
     * @param clientID
     * @param ersatzID
     * @return
     */
    public static Permission getErsatzChain(PermissionsStore permissionsStore, Identifier adminID, Identifier clientID, Identifier ersatzID) {
        PermissionList pList = permissionsStore.getErsatzChains(adminID, clientID);
        for (Permission p : pList) {
            if (p.canSubstitute()) {
                if (p.getErsatzChain().get(p.getErsatzChain().size() - 1).equals(ersatzID)) {
                    return p;
                }
            }
        }
        return null;
    }


    /**
     * used in {@link PermissionFileStore} and {@link PermissionMemoryStore} since they must iterate.
     *
     * @param adminID
     * @param clientID
     * @return
     */
    public static PermissionList getErsatzChains(PermissionsStore<? extends Permission> pStore, Identifier adminID, Identifier clientID) {
        PermissionList permissions = new PermissionList();
        for (Identifier id : pStore.keySet()) {
            Permission permission = pStore.get(id);
            if (permission.canSubstitute() && permission.getAdminID().equals(adminID) && permission.getClientID().equals(clientID)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }

    public static PermissionList getProvisioners(PermissionsStore<? extends Permission> pStore, Identifier adminID, Identifier ersatzID) {
        PermissionList permissions = new PermissionList();
        for (Identifier id : pStore.keySet()) {
            Permission permission = pStore.get(id);
            if (permission.canSubstitute() && permission.getAdminID().equals(adminID) && permission.getErsatzChain().contains(ersatzID)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }

    public static PermissionList getByAdminID(PermissionsStore<? extends Permission> pStore, Identifier adminID) {
        PermissionList permissions = new PermissionList();
        for (Identifier id : pStore.keySet()) {
            Permission permission = pStore.get(id);
            if (permission.getAdminID().equals(adminID)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }

    public static PermissionList getByClientID(PermissionsStore<? extends Permission> pStore, Identifier clientID) {
        PermissionList permissions = new PermissionList();
        for (Identifier id : pStore.keySet()) {
            Permission permission = pStore.get(id);
            if (permission.getClientID().equals(clientID)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }
    public static PermissionList getByErsatzID(PermissionsStore<? extends Permission> pStore, Identifier ersatzID) {
        PermissionList permissions = new PermissionList();
        for (Identifier id : pStore.keySet()) {
            Permission permission = pStore.get(id);
            if (permission.getErsatzChain().contains(ersatzID)) {
                permissions.add(permission);
            }
        }
        return permissions;
    }
}
