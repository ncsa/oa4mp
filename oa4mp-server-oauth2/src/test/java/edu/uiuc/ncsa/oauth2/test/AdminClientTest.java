package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.*;
import edu.uiuc.ncsa.security.util.TestBase;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  11:40 AM
 */
public class AdminClientTest extends TestBase {
    public void testFS() throws Exception {
        testAdminClient(((TestStoreProvider2) TestUtils.getFsStoreProvider()).getAdminClientStore());
      }

      public void testMYSQL() throws Exception {
          testAdminClient(((TestStoreProvider2)TestUtils.getMySQLStoreProvider()).getAdminClientStore());
      }

      public void testMemStore() throws Exception {
          testAdminClient(((TestStoreProvider2) TestUtils.getMemoryStoreProvider()).getAdminClientStore());
      }

      public void testPG() throws Exception {
          testAdminClient(((TestStoreProvider2) TestUtils.getPgStoreProvider()).getAdminClientStore());
      }



    public void testAdminClient(AdminClientStore store) throws Exception {
        AdminClientProvider clientProvider = new AdminClientProvider();
        AdminClientConverter converter = new AdminClientConverter(new AdminClientKeys(), clientProvider);

        AdminClient c = (AdminClient) store.create();
        c.setSecret("idufh84057thsdfghwre");
        c.setEmail("bob@foo.bar");
        c.setName("Test client 42");
        c.setIssuer("https://www.bigscience.org/claims");
        c.setVirtualOrganization("dfkjg9egh39yudfnwj9engidugnHIRH9wht9f");
        JSONObject j = new JSONObject();
        converter.toJSON(c, j);
        System.out.println(j);
        AdminClient c2 =  converter.fromJSON(j);
        assert c2.equals(c) : "admin clients not the same after conversion to then from JSON";
    }


}
