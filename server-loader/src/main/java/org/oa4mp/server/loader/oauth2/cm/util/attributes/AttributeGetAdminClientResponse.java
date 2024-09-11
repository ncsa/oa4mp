package org.oa4mp.server.loader.oauth2.cm.util.attributes;

import org.oa4mp.server.api.admin.adminClient.AdminClient;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/17 at  1:06 PM
 */
public class AttributeGetAdminClientResponse extends AttributeAdminClientResponse {
    public AttributeGetAdminClientResponse(AdminClient adminClient, List<String> attributes) {
        super(adminClient);
        this.attributes = attributes;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    List<String> attributes;
}
