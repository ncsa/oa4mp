package org.oa4mp.server.test;

import org.oa4mp.server.test.TestStoreProvider;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;

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
