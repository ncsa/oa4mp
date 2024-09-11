package org.oa4mp.server.loader.oauth2.cm.util.attributes;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  4:22 PM
 */
public class AttributeListRequest extends AttributeRequest {
    public AttributeListRequest(AdminClient adminClient, OA2Client client) {
        super(adminClient, client);
    }
}
