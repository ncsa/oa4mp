package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.admin;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/17 at  11:12 AM
 */
public class ACGetResponse extends AbstractACResponse {
    public ACGetResponse(AdminClient adminClient, boolean approved) {
        this.adminClient = adminClient;
        this.approved = approved;

    }

    public AdminClient getAdminClient() {
        return adminClient;
    }

    public void setAdminClient(AdminClient adminClient) {
        this.adminClient = adminClient;
    }

    AdminClient adminClient;

    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    boolean approved;
}
