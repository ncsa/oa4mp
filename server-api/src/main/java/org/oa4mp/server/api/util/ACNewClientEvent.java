package org.oa4mp.server.api.util;

import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.delegation.common.storage.clients.BaseClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/27/21 at  1:36 PM
 */
public class ACNewClientEvent extends NewClientEvent{
    public ACNewClientEvent(Object source, AdminClient adminClient, BaseClient client) {
        super(source, client);
        this.adminClient = adminClient;
    }

    public AdminClient getAdminClient() {
        return adminClient;
    }

    AdminClient adminClient;
}
