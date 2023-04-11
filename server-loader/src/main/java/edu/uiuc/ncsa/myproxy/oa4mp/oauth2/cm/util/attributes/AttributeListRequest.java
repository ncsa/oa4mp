package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  4:22 PM
 */
public class AttributeListRequest extends AttributeRequest {
    public AttributeListRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}
