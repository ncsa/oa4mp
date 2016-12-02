package edu.uiuc.ncsa.co.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  2:09 PM
 */
public class AddClientRequest extends PermissionRequest {
    public AddClientRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}
