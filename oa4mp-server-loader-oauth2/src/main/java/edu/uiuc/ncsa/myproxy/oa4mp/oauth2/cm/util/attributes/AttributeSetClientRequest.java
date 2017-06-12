package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  3:49 PM
 */
public class AttributeSetClientRequest extends AttributeRequest{
    public AttributeSetClientRequest(AdminClient adminClient, OA2Client client, Map<String, Object> attributes) {
        super(adminClient, client);
        this.attributes = attributes;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    Map<String, Object> attributes;


}
