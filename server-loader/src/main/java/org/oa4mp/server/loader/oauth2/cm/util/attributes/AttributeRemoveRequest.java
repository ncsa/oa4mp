package org.oa4mp.server.loader.oauth2.cm.util.attributes;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

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
