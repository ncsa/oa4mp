package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.security.util.TestBase;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/26/17 at  3:42 PM
 */
public class NewClientStoreTest extends TestBase {
    public void testFS() throws Exception {
        testBasic(TestUtils.getFsStoreProvider().getClientStore());
    }

    public void testMYSQL() throws Exception {
        testBasic(TestUtils.getMySQLStoreProvider().getClientStore());
    }

    public void testMemStore() throws Exception {
        testBasic(TestUtils.getMemoryStoreProvider().getClientStore());
    }

    public void testPG() throws Exception {
        testBasic(TestUtils.getPgStoreProvider().getClientStore());
    }

    public void testDerby() throws Exception {
        testBasic(TestUtils.getDerbyStoreProvider().getClientStore());
    }

  /*  public void testAG() throws Exception {
        testBasic(TestUtils.getAgStoreProvider().getClientStore());
    }

*/
    public void testBasic(ClientStore clientStore) throws Exception {
        Client client = (Client) clientStore.create();
        System.out.println("New client ID = " + client.getIdentifier());
        client.setHomeUri("urn:test:/home/uri");
        client.setSecret(getRandomString(256));
        client.setName("Test delegation client");
        client.setEmail("test@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri");
        client.setProxyLimited(true);
        clientStore.save(client);
        Client client2 = (Client) clientStore.get(client.getIdentifier());
        assert client.getIdentifier().equals(client2.getIdentifier());
        assert client.getHomeUri().equals(client2.getHomeUri());
        assert client.getSecret().equals(client2.getSecret());
        assert client.getName().equals(client2.getName());
        assert client.getEmail().equals(client2.getEmail());
        assert client.getErrorUri().equals(client2.getErrorUri());
        assert client2.isProxyLimited();

        clientStore.remove(client.getIdentifier());
    }
}
