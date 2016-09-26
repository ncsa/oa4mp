package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import org.junit.Test;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:51 PM
 */
public abstract class CAStoreTest extends StoreTest {

    public ClientApprovalStore<ClientApproval> getApprovalStore() throws Exception {
        return getTSProvider().getClientApprovalStore();
    }

    protected ClientStore<Client> getClientStore() throws Exception {
        return getTSProvider().getClientStore();
    }

    @Override
    public void checkStoreClass() throws Exception {
        testClassAsignability(getApprovalStore());
    }

    @Test
    public void testApprovalStore() throws Exception {
        // put one in, get it back, make sure it matches.
        Client client = getClientStore().create();

        client.setHomeUri("urn:test:/home/uri/" + getRandomString(32));
        client.setSecret(getRandomString(256));
        client.setName("Test client" + getRandomString(32));
        client.setEmail(getRandomString(32) + "@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri/" + getRandomString(32));
        getClientStore().save(client);

        ClientApproval ca = getApprovalStore().create();
        ca.setApprover("test-approver");
        ca.setApproved(true);
        ca.setApprovalTimestamp(new Date());
        ca.setIdentifier(client.getIdentifier());
        getApprovalStore().save(ca);

        ClientApproval ca1 = getApprovalStore().get(ca.getIdentifier());
        assert ca.equals(ca1);
        getApprovalStore().remove(ca.getIdentifier());
    }

    @Test
    public void testApprovalCycle() throws Exception {
        // approval of something not in the store means it is not approved.

        assert !getApprovalStore().isApproved(BasicIdentifier.newID("foo:bar:baz://" + getRandomString(32)));

        Client client = getClientStore().create();
        Identifier identifier = client.getIdentifier();

        client.setHomeUri("urn:test:/home/uri/" + getRandomString(32));
        client.setSecret(getRandomString(256));
        client.setName("Test client" + getRandomString(32));
        client.setEmail(getRandomString(32) + "@email.foo.edu");
        client.setErrorUri("uri:test:/uh/oh/uri/" + getRandomString(32));
        getClientStore().save(client);

        ClientApproval ca = getApprovalStore().create();
        ca.setApprover("test-approver");
        ca.setApproved(false);
        ca.setApprovalTimestamp(new Date());
        ca.setIdentifier(identifier);
        getApprovalStore().save(ca);

        assert !getApprovalStore().get(client.getIdentifier()).isApproved();

        assert !getApprovalStore().isApproved(identifier);
        ca.setApproved(true);
        getApprovalStore().save(ca);

        // Regression test to be sure that identifiers are never changed.
        assert identifier.equals(ca.getIdentifier());
        assert identifier.equals(client.getIdentifier());
        assert getApprovalStore().get(client.getIdentifier()).isApproved();
        assert getApprovalStore().isApproved(identifier);

        getApprovalStore().remove(client.getIdentifier());
        getClientStore().remove(client.getIdentifier());

    }
}
