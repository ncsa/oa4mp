package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.AbstractDDRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  10:57 AM
 */
public class PermissionRequest extends AbstractDDRequest{
    public PermissionRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

    @Override
    public Response process(Server server) {
        if(server instanceof PermissionServer) {
            if (this instanceof ListAdminsRequest) {
                return ((PermissionServer) server).listAdmins((ListAdminsRequest) this);
            }
            if (this instanceof ListClientsRequest) {
                return ((PermissionServer) server).listClients((ListClientsRequest) this);
            }
            if (this instanceof AddClientRequest) {
                return ((PermissionServer) server).addClient((AddClientRequest) this);
            }
            if (this instanceof RemoveClientRequest) {
                return ((PermissionServer) server).removeClient((RemoveClientRequest) this);
            }
            throw new GeneralException("Unknown action on permission server");
        }
        throw new NFWException("Incorrect server is invoking this method. Expected a PermissionServer and got a " + server.getClass().getSimpleName());
    }
}
