package org.oa4mp.server.loader.oauth2.cm.util.client;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  1:44 PM
 */
public class RemoveRequest extends ClientRequest {
    public RemoveRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}
