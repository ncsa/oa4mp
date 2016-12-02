package edu.uiuc.ncsa.co.util.client;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  12:51 PM
 */
public class CreateRequest extends ClientRequest {
    public CreateRequest(AdminClient adminClient, OA2Client client, Map<String,Object> attributes) {
        super(adminClient, client);
        this.attributes = attributes;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    Map<String,Object> attributes;
}
