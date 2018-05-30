package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  1:56 PM
 */
public class ListClientsRequest extends PermissionRequest {
    public ListClientsRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

}
