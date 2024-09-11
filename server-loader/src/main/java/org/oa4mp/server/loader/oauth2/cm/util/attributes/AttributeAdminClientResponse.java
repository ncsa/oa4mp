package org.oa4mp.server.loader.oauth2.cm.util.attributes;

import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.delegation.common.services.Response;

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
