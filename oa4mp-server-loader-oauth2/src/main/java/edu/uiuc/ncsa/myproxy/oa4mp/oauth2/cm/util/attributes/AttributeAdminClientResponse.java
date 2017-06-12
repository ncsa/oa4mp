package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.delegation.services.Response;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/17 at  1:04 PM
 */
public class AttributeAdminClientResponse implements Response {
    AdminClient adminClient;

    public AttributeAdminClientResponse(AdminClient adminClient) {
        this.adminClient = adminClient;
    }

    public AdminClient getAdminClient() {

        return adminClient;
    }

    public void setAdminClient(AdminClient adminClient) {
        this.adminClient = adminClient;
    }
}
