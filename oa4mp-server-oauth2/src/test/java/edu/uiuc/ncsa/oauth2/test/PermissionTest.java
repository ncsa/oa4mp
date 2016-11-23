package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.util.TestBase;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/18/16 at  2:16 PM
 */
public class PermissionTest extends TestBase {
    public void testFS() throws Exception {
        TestStoreProvider2 tp2 = (TestStoreProvider2) TestUtils.getFsStoreProvider();
        testPermission(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testAttributes(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testIDs(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());

    }

    public void testMYSQL() throws Exception {
        TestStoreProvider2 tp2 = (TestStoreProvider2) TestUtils.getMySQLStoreProvider();
        testPermission(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testAttributes(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testIDs(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
    }

    public void testMemStore() throws Exception {
        TestStoreProvider2 tp2 = (TestStoreProvider2) TestUtils.getMemoryStoreProvider();
        testPermission(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testAttributes(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testIDs(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
    }

    public void testPG() throws Exception {
        TestStoreProvider2 tp2 = (TestStoreProvider2) TestUtils.getPgStoreProvider();
        testPermission(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testAttributes(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
        testIDs(tp2.getPermissionStore(), tp2.getClientStore(), tp2.getAdminClientStore());
    }

    public void testPermission(PermissionsStore pStore, ClientStore clientStore, AdminClientStore acStore) throws Exception {
        AdminClient ac = (AdminClient) acStore.create();
        OA2Client c = (OA2Client) clientStore.create();


        Permission p = (Permission) pStore.create();
        p.setAdminID(ac.getIdentifier());
        p.setClientID(c.getIdentifier());
        pStore.save(p);
        assert pStore.hasEntry(ac.getIdentifier(), c.getIdentifier());
        List<Identifier> adminIds = pStore.getAdmins(c.getIdentifier());
        assert adminIds.contains(ac.getIdentifier());
        List<Identifier> clientIDs = pStore.getClients(ac.getIdentifier());
        assert clientIDs.contains(c.getIdentifier());
        // now to ttest for multiple additions
        pStore.save(p);
        pStore.save(p);
        assert pStore.getAdmins(c.getIdentifier()).size() == 1;
        assert pStore.getClients(ac.getIdentifier()).size() == 1;
        OA2Client c1 = (OA2Client) clientStore.create();
        Permission p1 = (Permission) pStore.create();
        p1.setApprove(false);
        p1.setAdminID(ac.getIdentifier());
        p1.setClientID(c1.getIdentifier());
        pStore.save(p1);
        assert pStore.getAdmins(c1.getIdentifier()).size() == 1;
        assert pStore.getClients(ac.getIdentifier()).size() == 2;


    }

    public void testAttributes(PermissionsStore pStore, ClientStore clientStore, AdminClientStore acStore) throws Exception {
        AdminClient ac = (AdminClient) acStore.create();
        OA2Client c = (OA2Client) clientStore.create();


        Permission p = (Permission) pStore.create();
        p.setAdminID(ac.getIdentifier());
        p.setClientID(c.getIdentifier());
        p.setApprove(false);
        pStore.save(p);
        Permission p2 = (Permission) pStore.get(p.getIdentifier());
        assert p2.equals(p);

        p.setCreate(false);
        pStore.save(p);
        p2 = (Permission) pStore.get(p.getIdentifier());
        assert p2.equals(p);

        p.setRead(false);
        pStore.save(p);
        p2 = (Permission) pStore.get(p.getIdentifier());
        assert p2.equals(p);

        p.setDelete(false);
        pStore.save(p);
        p2 = (Permission) pStore.get(p.getIdentifier());
        assert p2.equals(p);

        p.setDelete(false);
        pStore.save(p);
        p2 = (Permission) pStore.get(p.getIdentifier());
        assert p2.equals(p);


    }

    public void testIDs(PermissionsStore pStore, ClientStore clientStore, AdminClientStore acStore) throws Exception {
        AdminClient ac = (AdminClient) acStore.create();
        AdminClient ac2 = (AdminClient) acStore.create();
        OA2Client c = (OA2Client) clientStore.create();


        Permission p = (Permission) pStore.create();
        p.setAdminID(ac.getIdentifier());
        p.setClientID(c.getIdentifier());
        pStore.save(p);
        p.setAdminID(ac2.getIdentifier());
        System.out.println(p);
        pStore.save(p);
        Permission p2 = (Permission) pStore.get(p.getIdentifier());
        assert p2.getAdminID().equals(ac2.getIdentifier());
        assert pStore.hasEntry(ac2.getIdentifier(), c.getIdentifier());
        assert !pStore.hasEntry(ac.getIdentifier(), c.getIdentifier());
    }

}
