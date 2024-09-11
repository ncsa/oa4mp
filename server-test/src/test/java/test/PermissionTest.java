package test;

import org.oa4mp.server.test.TestUtils;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.util.TestBase;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/18/16 at  2:16 PM
 */
public class PermissionTest extends TestBase {
    public void testFS() throws Exception {
        doTestAll((TestStoreProvider2) TestUtils.getFsStoreProvider());
    }

    public void testMYSQL() throws Exception {
        doTestAll((TestStoreProvider2) TestUtils.getMySQLStoreProvider());
    }

    public void testMemStore() throws Exception {
        doTestAll((TestStoreProvider2) TestUtils.getMemoryStoreProvider());
    }

    public void testPG() throws Exception {
        doTestAll((TestStoreProvider2) TestUtils.getPgStoreProvider());
    }

    public void testDerby() throws Exception {
        doTestAll((TestStoreProvider2) TestUtils.getDerbyStoreProvider());
    }

    protected void doTestAll(TestStoreProvider2 tp2) throws Exception{
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
