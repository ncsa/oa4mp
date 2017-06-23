package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.delegation.services.Request;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

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
