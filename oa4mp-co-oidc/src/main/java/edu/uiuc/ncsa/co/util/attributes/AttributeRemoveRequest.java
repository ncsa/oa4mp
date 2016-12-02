package edu.uiuc.ncsa.co.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  4:19 PM
 */
public class AttributeRemoveRequest extends AttributeRequest {
    public AttributeRemoveRequest(AdminClient adminClient, OA2Client client, List<String> attributes) {
        super(adminClient, client);
        this.attributes = attributes;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    List<String> attributes;
}
