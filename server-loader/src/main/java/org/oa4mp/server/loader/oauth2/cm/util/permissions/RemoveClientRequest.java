package org.oa4mp.server.loader.oauth2.cm.util.permissions;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  11:20 AM
 */
public class RemoveClientRequest extends PermissionRequest {
    public RemoveClientRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

}
