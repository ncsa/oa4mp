package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader.COSE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.AbstractDDServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.LinkedList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  10:54 AM
 */
public class PermissionServer extends AbstractDDServer {
    public PermissionServer(COSE cose) {
        super(cose);
    }

    /**
     * Returns a list of admins for a given client. This will check that the permissions exist for this operation.
     *
     * @param request
     * @return
     */
    public PermissionResponse listAdmins(ListAdminsRequest request) {
        // request needs an client id
        // canRead(request);
        List<Identifier> adminIDs = getPermissionStore().getAdmins(request.getClient().getIdentifier());
        List<AdminClient> admins = new LinkedList<>();
        for (Identifier id : adminIDs) {
            try {
                getPermissionStore().get(id, request.getClient().getIdentifier());
                admins.add(getAdminClientStore().get(id));
            } catch (Throwable t) {
                // rock on
            }
        }
        return new ListAdminsResponse(admins);
    }


    public PermissionResponse listClients(ListClientsRequest request) {
        // request needs an admin client only
//        canRead(request);
        List<Identifier> clientIDs = getPermissionStore().getClients(request.getAdminClient().getIdentifier());
        List<OA2Client> clients = new LinkedList<>();
        for (Identifier id : clientIDs) {
            try {
                getPermissionStore().get(request.getAdminClient().getIdentifier(), id);
                clients.add((OA2Client) getClientStore().get(id));
            } catch (Throwable throwable) {
                // rock on if not allowed
            }
        }
        return new ListClientResponse(clients);
    }

    /**
     * removes a client from management by an admin. This does NOT remove the client!!
     *
     * @param request
     * @return
     */
    public PermissionResponse removeClient(RemoveClientRequest request) {
        // request needs admin as src, client as target
        canWrite(request);
        PermissionList permissionList = getPermissionStore().get(request.getAdminClient().getIdentifier(), request.getClient().getIdentifier());
        // remove all of these permissions
        for (Permission p : permissionList) {
            getPermissionStore().remove(p.getIdentifier());
        }
        return new PermissionResponse();
    }

    /**
     * Adds a given client to the list of clients managed by this admin
     *
     * @param request
     * @return
     */
    public PermissionResponse addClient(AddClientRequest request) {
        //request needs admin and client.
        // Check if there is one already -- don't fill up table with redundant permissions.
        Permission p = null;
        PermissionList pList = getPermissionStore().get(request.getAdminClient().getIdentifier(), request.getClient().getIdentifier());
        switch (pList.size()) {
            case 0:
                p = getPermissionStore().create();
                break;
            case 1:
                p = pList.get(0);
                break;
            default:
                throw new GeneralException("Internal error. Multiple permissiions entries found");

        }
        p.setAdminID(request.getAdminClient().getIdentifier());
        p.setClientID(request.getClient().getIdentifier());
        p.setApprove(true);
        p.setCreate(true);
        p.setDelete(true);
        p.setRead(true);
        p.setWrite(true);
        getPermissionStore().save(p);
        return new AddClientResponse();
    }

}
