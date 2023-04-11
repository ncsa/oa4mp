package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;

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
