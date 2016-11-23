package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  11:10 AM
 */
public abstract class TestStoreProvider2 extends TestStoreProvider {
    protected OA2SE getOA2SE() {
        return (OA2SE) getSE();
    }

    public PermissionsStore<Permission> getPermissionStore() throws Exception {
        return getOA2SE().getPermissionStore();
    }

    public AdminClientStore<AdminClient> getAdminClientStore() throws Exception {
        return getOA2SE().getAdminClientStore();
    }
}
