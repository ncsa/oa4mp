package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 25, 2011 at  2:59:59 PM
 */
public abstract class ClientStoreTest extends StoreTest {


    public ClientStore<Client> getClientStore() throws Exception {
        return getTSProvider().getClientStore();
    }

    @Override
    public void checkStoreClass() throws Exception {
        testClassAsignability(getClientStore());
    }


    @Test
    public void testBasic() throws Exception {
        Client client = getClientStore().create();
        System.out.println("New client ID = " + client.getIdentifier());
        client.setHomeUri("urn:test:/home/uri");
        client.setSecret(getRandomString(256));
        client.setName("Test delegation client");
        client.setEmail("test@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri");
        client.setProxyLimited(true);
        getClientStore().save(client);
        Client client2 = getClientStore().get(client.getIdentifier());
        assert client.equals(client2);
        getClientStore().remove(client.getIdentifier());
    }
}
