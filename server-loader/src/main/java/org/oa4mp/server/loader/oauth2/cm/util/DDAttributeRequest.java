package org.oa4mp.server.loader.oauth2.cm.util;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

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
