package test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.*;
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
        c.setVirtualOrganization("dfkjg9egh39yudfnwj9engidugnHIRH9wht9f");
        c.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS + 100);
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        System.out.println(j);
        AdminClient c2 = converter.fromJSON(j);
        assert c2.equals(c) : "admin clients not the same after conversion to then from JSON";
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
        c.setLastModifiedTS(new Date(1000L));
        c.setSecret("idufh84057thsdfghwre");
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        c.setIssuer("https://www.bigscience.org/claims");
        c.setVirtualOrganization("dfkjg9egh39yudfnwj9engidugnHIRH9wht9f");
        c.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS + 100);
        Date nowDate = new Date();
        long now = nowDate.getTime();
        store.save(c);
        AdminClient c2 = (AdminClient) store.get(c.getIdentifier());
        long lastMod = c2.getLastModifiedTS().getTime();
        // Since the last modified is created at save time,
        // these might not match up exactly. We therefore check that they are within a narrow range.
        System.out.println("last modified is " + c2.getLastModifiedTS() + " and the timestamp is " + nowDate);
        assert c.equals(c2);
        assert now - comparisonTolerance <= lastMod && lastMod <= now + comparisonTolerance: "timestamp " + lastMod + " failed to be within tolerance " + comparisonTolerance + " for now " + now + ", difference =" + (lastMod - now);
        // clean up.
        store.remove(c.getIdentifier());
    }


}
