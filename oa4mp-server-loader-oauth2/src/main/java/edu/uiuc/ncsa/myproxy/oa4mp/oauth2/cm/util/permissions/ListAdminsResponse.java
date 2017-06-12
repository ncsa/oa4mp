package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  11:05 AM
 */
public class ListAdminsResponse extends PermissionResponse {
    public ListAdminsResponse(List<AdminClient> admins) {
        this.admins = admins;
    }

    public List<AdminClient> getAdmins() {
        return admins;
    }

    List<AdminClient> admins;
}
