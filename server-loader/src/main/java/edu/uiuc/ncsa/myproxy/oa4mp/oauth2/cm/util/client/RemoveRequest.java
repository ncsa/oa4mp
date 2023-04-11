package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  1:44 PM
 */
public class RemoveRequest extends ClientRequest {
    public RemoveRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}
