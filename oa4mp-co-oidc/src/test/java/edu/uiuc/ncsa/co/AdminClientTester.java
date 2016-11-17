package edu.uiuc.ncsa.co;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.*;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/16 at  11:40 AM
 */
public class AdminClientTester {
    public static void main(String[] args) {
        acTest();
    }

    protected static void acTest() {

        AdminClientProvider clientProvider = new AdminClientProvider();

        AdminClientMemoryStore store = new AdminClientMemoryStore(clientProvider);

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
        AdminClient c2 = (AdminClient) converter.fromJSON(j);
        System.out.println("equal?" + c2.equals(c));


    }
}
