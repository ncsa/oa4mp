package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.delegation.services.Response;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/17 at  1:42 PM
 */
public class AttributeSetAdminClientResponse implements Response {
    public AttributeSetAdminClientResponse(AdminClient adminClient, Map<String, Object> attributes) {
        this.adminClient = adminClient;
        this.attributes = attributes;
    }

    AdminClient adminClient;

    public AdminClient getAdminClient() {
        return adminClient;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    Map<String, Object> attributes;
}
