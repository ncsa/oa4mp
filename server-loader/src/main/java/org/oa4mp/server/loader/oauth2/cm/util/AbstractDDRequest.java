package org.oa4mp.server.loader.oauth2.cm.util;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.delegation.common.services.Request;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  3:21 PM
 */
public abstract class AbstractDDRequest implements Request {
    protected AdminClient adminClient;
    protected OA2Client client;

    public AbstractDDRequest(AdminClient adminClient, OA2Client client) {
        this.adminClient = adminClient;
        this.client = client;
    }


    public AdminClient getAdminClient() {
        return adminClient;
    }

    public OA2Client getClient() {
        return client;
    }

    public boolean hasAdminClient() {
        return adminClient != null && adminClient.getIdentifier() != null && adminClient.getIdentifierString().length() != 0;
    }

    public boolean hasClient() {
        return client != null && client.getIdentifier() != null && client.getIdentifierString().length() != 0;
    }
}
