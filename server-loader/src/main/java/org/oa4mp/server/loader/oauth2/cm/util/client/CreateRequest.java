package org.oa4mp.server.loader.oauth2.cm.util.client;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

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
