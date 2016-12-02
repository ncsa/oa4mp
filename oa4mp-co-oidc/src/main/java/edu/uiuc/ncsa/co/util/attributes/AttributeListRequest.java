package edu.uiuc.ncsa.co.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  4:22 PM
 */
public class AttributeListRequest extends AttributeRequest {
    public AttributeListRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}
