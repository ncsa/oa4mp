package org.oa4mp.server.api.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  4:16 PM
 */
public interface PermissionsStore<V extends Permission> extends Store<V> {
    /**
     * A list of all identifiers that a given admin can manage.
     *
     * @param adminID
     * @return
     */
    List<Identifier> getClients(Identifier adminID);

    /**
     * A list of all admin ids for a given client.
     *
     * @param clientID
     * @return
     */
    List<Identifier> getAdmins(Identifier clientID);

    /**
     * Retrieve a permission from the admin and client identifier.
     *
     * @param adminID
     * @param clientID
     * @return
     */

    PermissionList get(Identifier adminID, Identifier clientID);

    /**
     * Returns the chain of ersatz clients for a given admin and provisioning client.
     * Access the list using {@link Permission#getErsatzChain()}.
     *
     * @param adminID
     * @param clientID
     * @return
     */
    PermissionList getErsatzChains(Identifier adminID, Identifier clientID);

    PermissionList getProvisioners(Identifier adminID, Identifier ersatzID);

    /**
     * Get the specific permission with the chain starting with clientID and ending with ersatzID.
     *
     * @param adminID
     * @param clientID
     * @param ersatzID
     * @return
     */
    Permission getErsatzChain(Identifier adminID, Identifier clientID, Identifier ersatzID);

    /**
     * Returns whether or not there is an entry for this pair of identifiers. There is at most
     * one permission for any such pair
     *
     * @param adminID
     * @param clientID
     * @return
     */
    boolean hasEntry(Identifier adminID, Identifier clientID);

    int getClientCount(Identifier adminID);

    MapConverter getMapConverter();

    List<Permission> getByAdminID(Identifier adminID);

    List<Permission> getByClientID(Identifier clientID);

        List<Permission> getByErsatzID(Identifier ersatzID);
}
