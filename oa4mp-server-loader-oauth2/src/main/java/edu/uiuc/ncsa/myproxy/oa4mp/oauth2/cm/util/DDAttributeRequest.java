package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  12:59 PM
 */
public abstract class DDAttributeRequest extends AbstractDDRequest {
    public DDAttributeRequest(AdminClient adminClient, OA2Client client, List<String> attributes) {
        super(adminClient, client);
        this.attributes = attributes;
    }

    List<String> attributes;

    public List<String> getAttributes() {
        return attributes;
    }
}
