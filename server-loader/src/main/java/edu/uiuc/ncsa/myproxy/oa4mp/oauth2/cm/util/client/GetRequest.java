package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/5/16 at  2:03 PM
 */
public class GetRequest extends ClientRequest {
    public GetRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }

}
