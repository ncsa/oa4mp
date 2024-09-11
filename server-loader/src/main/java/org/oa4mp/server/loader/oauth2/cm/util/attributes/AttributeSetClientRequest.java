package org.oa4mp.server.loader.oauth2.cm.util.attributes;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

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
