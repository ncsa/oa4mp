package org.oa4mp.server.api.util;

import org.oa4mp.server.api.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/27/21 at  1:36 PM
 */
public class NewAdminClientEvent  extends NewClientEvent{
    public NewAdminClientEvent(Object source, AdminClient client) {
        super(source, client);
    }
}
