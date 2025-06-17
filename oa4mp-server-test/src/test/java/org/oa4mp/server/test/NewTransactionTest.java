package org.oa4mp.server.test;

import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.TestBase;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.server.OA2TokenForge;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.api.OA4MPServiceTransaction;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/26/17 at  4:01 PM
 */
public class NewTransactionTest extends TestBase {
    // Note that if a test fails for the FS because of missing column, the derby
    // script in /home/ncsa/dev/ncsa-git/oa4mp/server-admin/src/main/resources/oa4mp-derby.sql
    // is missing the new column. Remove the test database in /tmp/test, fix the sql table
    // create statements and retry.
    // This is a regression test that ensures the SQL script for Derby is up to date!
    public void testFS() throws Exception {
        serviceTransactionTest(TestUtils.getFsStoreProvider().getTransactionStore(),
                TestUtils.getFsStoreProvider().getTokenForge(),
                TestUtils.getFsStoreProvider().getClientStore());
    }

    public void testMYSQL() throws Exception {
        serviceTransactionTest(TestUtils.getMySQLStoreProvider().getTransactionStore(),
                TestUtils.getMySQLStoreProvider().getTokenForge(),
                TestUtils.getMySQLStoreProvider().getClientStore());
    }

    public void testMemStore() throws Exception {
        serviceTransactionTest(TestUtils.getMemoryStoreProvider().getTransactionStore(),
                TestUtils.getMemoryStoreProvider().getTokenForge(),
                TestUtils.getMemoryStoreProvider().getClientStore());
    }

    public void testPG() throws Exception {
        serviceTransactionTest(TestUtils.getPgStoreProvider().getTransactionStore(),
                TestUtils.getPgStoreProvider().getTokenForge(),
                TestUtils.getPgStoreProvider().getClientStore());
    }

    public void testDerby() throws Exception {
        serviceTransactionTest(TestUtils.getDerbyStoreProvider().getTransactionStore(),
                TestUtils.getDerbyStoreProvider().getTokenForge(),
                TestUtils.getDerbyStoreProvider().getClientStore());
    }

    protected AuthorizationGrant newAG(TokenForge tokenForge, String... x) {
        AuthorizationGrant ag = tokenForge.getAuthorizationGrant(x);
        // The forge may return a shared secret. Since we never use this in OA4MP, make sure it is null
        // or you will get false test results since the secret won't be stored.
        //    ag.setSharedSecret(null);
        return ag;
    }

     protected AccessToken newAT(TokenForge tokenForge, String... x) {
        AccessToken at = tokenForge.getAccessToken(x);
        //     at.setSharedSecret(null);
        return at;
    }

    public void serviceTransactionTest(TransactionStore transactionStore, TokenForge tokenForge, ClientStore clientStore) throws Exception {
        String randomString =  getRandomString();
        OA4MPServiceTransaction serviceTransaction = (OA4MPServiceTransaction) transactionStore.create();
        serviceTransaction.setCallback(URI.create("http://callback"));
        AuthorizationGrant ag = tokenForge.getAuthorizationGrant(serviceTransaction.getIdentifierString());
        serviceTransaction.setAuthorizationGrant(ag);
        serviceTransaction.setLifetime(10 * 60 * 60 * 1000); // set lifetime to 10 hours (stored in ms!)
        serviceTransaction.setUsername("FakeUserName");
        String mpUN = "myproxy username /with weird $$#@ in=it/#" + System.nanoTime();
        serviceTransaction.setMyproxyUsername(mpUN);
        Client client = (Client) clientStore.create();
        client.setIdentifier(new BasicIdentifier(URI.create("test:client:1d/" + randomString)));
        //serviceTransaction.setAuthorizationGrant(newAG(tokenForge));
        serviceTransaction.setAuthGrantValid(false);
        serviceTransaction.setClient(client);
        client.setName("service test name #" + System.nanoTime());
        // Add current time or the semantics are off and these do not get garbage collected
        OA2TokenForge  tf = new OA2TokenForge("https://localhost/" + randomString);
        serviceTransaction.setAccessToken(tf.getAccessToken());
        transactionStore.save(serviceTransaction);
        clientStore.save(client);
        assert transactionStore.containsKey(serviceTransaction.getIdentifier());
        assert serviceTransaction.equals(transactionStore.get(serviceTransaction.getIdentifier()));
        // Contract has changed in version 5.0+, so auth grant is now
        assert serviceTransaction.equals(transactionStore.get(serviceTransaction.getAuthorizationGrant()));
        // now emulate doing oauth type transactions with it.
        // First leg sets the verifier and user

        transactionStore.save(serviceTransaction);

        // next leg creates the access tokens and invalidates the temp credentials
        serviceTransaction.setAccessToken(newAT(tokenForge));
        serviceTransaction.setAuthGrantValid(false);
        serviceTransaction.setAccessTokenValid(true);
        transactionStore.save(serviceTransaction);
        assert serviceTransaction.equals(transactionStore.get(serviceTransaction.getIdentifier()));
        assert serviceTransaction.equals(transactionStore.get(serviceTransaction.getAccessToken()));
        serviceTransaction.setAccessTokenValid(false);
        transactionStore.save(serviceTransaction);
        assert serviceTransaction.equals(transactionStore.get(serviceTransaction.getIdentifier()));
        //and we're done
        serviceTransaction.setClient(client);
        transactionStore.remove(serviceTransaction.getIdentifier());
        assert !transactionStore.containsKey(serviceTransaction.getIdentifier());
        clientStore.remove(client.getIdentifier());
    }
}
