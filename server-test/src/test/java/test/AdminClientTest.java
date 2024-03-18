package test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.Pacer;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.util.TestBase;
import net.sf.json.JSONObject;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  11:40 AM
 */
public class AdminClientTest extends TestBase {
    public void testFS() throws Exception {
        testAdminClient(((TestStoreProvider2) TestUtils.getFsStoreProvider()).getAdminClientStore());
        testAdminClientConverter(((TestStoreProvider2) TestUtils.getFsStoreProvider()).getAdminClientStore());
    }

    public void testMYSQL() throws Exception {
        testAdminClient(((TestStoreProvider2) TestUtils.getMySQLStoreProvider()).getAdminClientStore());
        testAdminClientConverter(((TestStoreProvider2) TestUtils.getMySQLStoreProvider()).getAdminClientStore());
    }

    public void testMemStore() throws Exception {
        testAdminClient(((TestStoreProvider2) TestUtils.getMemoryStoreProvider()).getAdminClientStore());
        testAdminClientConverter(((TestStoreProvider2) TestUtils.getMemoryStoreProvider()).getAdminClientStore());
    }

    public void testPG() throws Exception {
        testAdminClient(((TestStoreProvider2) TestUtils.getPgStoreProvider()).getAdminClientStore());
        testAdminClientConverter(((TestStoreProvider2) TestUtils.getPgStoreProvider()).getAdminClientStore());
    }

    public void testDerby() throws Exception {
        testAdminClient(((TestStoreProvider2) TestUtils.getDerbyStoreProvider()).getAdminClientStore());
        testAdminClientConverter(((TestStoreProvider2) TestUtils.getDerbyStoreProvider()).getAdminClientStore());
    }

    /**
     * Test that creating and populating a new admin client then converting to then from JSON
     * does not alter the values of the fields
     *
     * @param store
     * @throws Exception
     */
    public void testAdminClientConverter(AdminClientStore store) throws Exception {
        AdminClientProvider clientProvider = new AdminClientProvider();
        AdminClientConverter converter = new AdminClientConverter(new AdminClientKeys(), clientProvider);

        AdminClient c = (AdminClient) store.create();
        c.setLastModifiedTS(new Date(1000L));
        c.setSecret("idufh84057thsdfghwre");
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        c.setIssuer("https://www.bigscience.org/claims");
        c.setVirtualOrganization(BasicIdentifier.randomID());
        c.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS + 100);
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        System.out.println(j);
        AdminClient c2 = converter.fromJSON(j);
        assert c.getLastModifiedTS().getTime() == c2.getLastModifiedTS().getTime();
        assert c.getSecret().equals(c2.getSecret());
        assert c.getEmail().equals(c2.getEmail());
        assert c.getName().equals(c2.getName());
        assert c.getIssuer().equals(c2.getIssuer());
        assert c.getVirtualOrganization().equals(c2.getVirtualOrganization());
        assert c.getMaxClients() == c2.getMaxClients();
        //   assert c2.equals(c) : "admin clients not the same after conversion to then from JSON";
        // clean up.
        store.remove(c.getIdentifier());

    }

    /**
     * Test that saving an admin client preserves values and that the last modified TS is
     * updated to the most recent time
     *
     * @param store
     * @throws Exception
     */
    public void testAdminClient(AdminClientStore store) throws Exception {
        long comparisonTolerance = 1000L; // for one second
        AdminClientProvider clientProvider = new AdminClientProvider();
        AdminClientConverter converter = new AdminClientConverter(new AdminClientKeys(), clientProvider);

        AdminClient c = (AdminClient) store.create();
        c.setLastModifiedTS(new Date(1009000L));
        c.setSecret("idufh84057thsdfghwre");
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        c.setIssuer("https://www.bigscience.org/claims");
        c.setVirtualOrganization(BasicIdentifier.randomID());
        c.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS + 100);
        Date nowDate = new Date();
        long now = nowDate.getTime();
        store.save(c);
        AdminClient c2 = (AdminClient) store.get(c.getIdentifier());
        long lastMod = c2.getLastModifiedTS().getTime();
        // Since the last modified is created at save time,
        // these might not match up exactly. We therefore check that they are within a narrow range.
        assert c.getIdentifier().equals(c2.getIdentifier());
        assert c.getSecret().equals(c2.getSecret());
        assert c.getEmail().equals(c2.getEmail());
        assert c.getName().equals(c2.getName());
        assert c.getIssuer().equals(c2.getIssuer());
        assert c.getVirtualOrganization().equals(c2.getVirtualOrganization());
        assert c.getMaxClients() == c2.getMaxClients();
        assert now - comparisonTolerance <= lastMod && lastMod <= now + comparisonTolerance : "timestamp " + lastMod + " failed to be within tolerance " + comparisonTolerance + " for now " + now + ", difference =" + (lastMod - now);
        // clean up.
        store.remove(c.getIdentifier());
    }

    public void testBigAdminClientStore() throws Exception {
        // This method is for debugging a massive file store. The next conditional
        // means this is always skipped unless you comment it out. It makes a
        // quarter of a million file in about half a minute.

        if (!doBigStore) return;

        AdminClientStore store = TestUtils.getOLDfsStoreProvider().getAdminClientStore();
        ClientStore clientStore = TestUtils.getOLDfsStoreProvider().getClientStore();
        ClientApprovalStore clientApprovalStore = TestUtils.getOLDfsStoreProvider().getClientApprovalStore();
        PermissionsStore permissionsStore = TestUtils.getOLDfsStoreProvider().getPermissionStore();

        FileStore fileStore = (FileStore) store;
        String random = getRandomString(8);
        Date now = new Date();
        Pacer pacer = new Pacer(20);
        long startTime = System.currentTimeMillis();
        int count = 100;
        System.out.println("creating " + count + " files in " + fileStore.getStorageDirectory().getAbsolutePath());
        for (int i = 0; i < count; i++) {
            AdminClient adminClient = (AdminClient) store.create();
            adminClient.setSecret(getRandomString(100));
            adminClient.setName("name-" + random);
            adminClient.setEmail("bob@" + random + "bgsu.edu");
            adminClient.setCreationTS(now);
            adminClient.setLastModifiedTS(now);
            adminClient.setIssuer("issuer:" + random);
            if (i % 47 == 0) {
                adminClient.setLastAccessed(now);
            }
            adminClient.setDescription("big test admin client batch:" + random);
            adminClient.setConfig(createRandomJSON());
            store.register(adminClient);
            for (int j = 0; j < 10; j++) {
                OA2Client oa2Client = (OA2Client) clientStore.create();
                ClientApproval clientApproval = (ClientApproval) clientApprovalStore.create();
                clientApproval.setIdentifier(oa2Client.getIdentifier());
                Permission p = new Permission(BasicIdentifier.randomID());
                p.setAdminID(adminClient.getIdentifier());
                p.setClientID(oa2Client.getIdentifier());
                clientApproval.setStatus(ClientApproval.Status.APPROVED);
                clientApproval.setApproved(true);
                clientApproval.setApprover("bob-" + random);
                clientStore.register(oa2Client);
                clientApprovalStore.register(clientApproval);
                permissionsStore.register(p);
            }
            if (i % 20 == 0) {
                pacer.pace(i, "files saved, " + (i * 100.0 / count) + "% done.");
            }
        }
        System.out.println("\n"+count + " files processed in " + (System.currentTimeMillis() - startTime) + "ms.");
    }

    boolean doBigStore = false;

    public void testBigClientStore() throws Exception {
        // This method is for debugging a massive file store.  It makes a
        // quarter of a million file in about half a minute.
        if (!doBigStore) return;
        ClientStore store = TestUtils.getOLDfsStoreProvider().getClientStore();
        ClientApprovalStore clientApprovalStore = TestUtils.getOLDfsStoreProvider().getClientApprovalStore();
        FileStore fileStore = (FileStore) store;
        String random = getRandomString(8);
        Date now = new Date();

        Pacer pacer = new Pacer(20);
        long startTime = System.currentTimeMillis();
        int count = 100000;
        System.out.println("creating " + count + " files in " + fileStore.getStorageDirectory().getAbsolutePath());
        for (int i = 0; i < count; i++) {

            OA2Client client = (OA2Client) store.create();
            client.setSecret(getRandomString(100));
            client.setName("name-" + random);
            client.setEmail("bob@" + random + "bgsu.edu");
            client.setCreationTS(now);
            client.setLastModifiedTS(now);
            ClientApproval clientApproval = (ClientApproval) clientApprovalStore.create();
            clientApproval.setIdentifier(client.getIdentifier());
            clientApproval.setApprover("tom" + random);
            clientApproval.setApproved(true);
            clientApproval.setStatus(ClientApproval.Status.APPROVED);
            clientApproval.setApprovalTimestamp(now);
            if (i % 47 == 0) {
                client.setLastAccessed(now);
            }
            client.setDescription("big test client batch:" + random);
            client.setConfig(createRandomJSON());
            store.register(client);
            clientApprovalStore.register(clientApproval);
            if (i % 1000 == 0) {
                pacer.pace(i, "files saved, " + (i * 100.0 / count) + "% done.");
            }
        }
        System.out.println(count + " files processed in " + (System.currentTimeMillis() - startTime) + "ms.");
    }

    protected JSONObject createRandomJSON() {
        JSONObject jsonObject = new JSONObject();
        for (int i = 0; i < 10; i++) {
            jsonObject.put(getRandomString(10), getRandomString(100));
        }
        return jsonObject;
    }
}
