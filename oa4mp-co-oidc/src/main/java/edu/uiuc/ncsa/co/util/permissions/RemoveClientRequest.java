package edu.uiuc.ncsa.co.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  11:20 AM
 */
public class RemoveClientRequest extends PermissionRequest {
    public RemoveClientRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

}
