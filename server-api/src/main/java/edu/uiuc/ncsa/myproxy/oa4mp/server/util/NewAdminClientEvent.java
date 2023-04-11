package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/27/21 at  1:36 PM
 */
public class NewAdminClientEvent  extends NewClientEvent{
    public NewAdminClientEvent(Object source, AdminClient client) {
        super(source, client);
    }
}
