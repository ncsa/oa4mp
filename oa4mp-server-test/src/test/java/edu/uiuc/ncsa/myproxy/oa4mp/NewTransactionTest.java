package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import edu.uiuc.ncsa.security.util.TestBase;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/26/17 at  4:01 PM
 */
public class NewTransactionTest extends TestBase {
    public void testFS() throws Exception {
        testServiceTransaction(TestUtils.getFsStoreProvider().getTransactionStore(),
                TestUtils.getFsStoreProvider().getTokenForge(),
                TestUtils.getFsStoreProvider().getClientStore());
    }

    public void testMYSQL() throws Exception {
        testServiceTransaction(TestUtils.getMySQLStoreProvider().getTransactionStore(),
                TestUtils.getMySQLStoreProvider().getTokenForge(),
                TestUtils.getMySQLStoreProvider().getClientStore());
    }

    public void testMemStore() throws Exception {
        testServiceTransaction(TestUtils.getMemoryStoreProvider().getTransactionStore(),
                TestUtils.getMemoryStoreProvider().getTokenForge(),
                TestUtils.getMemoryStoreProvider().getClientStore());
    }

    public void testPG() throws Exception {
        testServiceTransaction(TestUtils.getPgStoreProvider().getTransactionStore(),
                TestUtils.getPgStoreProvider().getTokenForge(),
                TestUtils.getPgStoreProvider().getClientStore());
    }

  /*  public void testAG() throws Exception {
        testServiceTransaction(TestUtils.getAgStoreProvider().getTransactionStore(),
                TestUtils.getAgStoreProvider().getTokenForge(),
                TestUtils.getAgStoreProvider().getClientStore());
    }*/

    protected AuthorizationGrant newAG(TokenForge tokenForge, String... x) {
        AuthorizationGrant ag = tokenForge.getAuthorizationGrant(x);
        // The forge may return a shared secret. Since we never use this in OA4MP, make sure it is null
        // or you will get false test results since the secret won't be stored.
        ag.setSharedSecret(null);
        return ag;
    }

    protected Verifier newVerifier(TokenForge tokenForge, String... x) {
        return tokenForge.getVerifier(x);
    }

    protected AccessToken newAT(TokenForge tokenForge, String... x) {
        AccessToken at = tokenForge.getAccessToken(x);
        at.setSharedSecret(null);
        return at;
    }

    public void testServiceTransaction(TransactionStore transactionStore, TokenForge tokenForge, ClientStore clientStore) throws Exception {
        OA4MPServiceTransaction OA4MPServiceTransaction = (OA4MPServiceTransaction) transactionStore.create();
        OA4MPServiceTransaction.setCallback(URI.create("http://callback"));

        OA4MPServiceTransaction.setLifetime(10 * 60 * 60 * 1000); // set lifetime to 10 hours (stored in ms!)
        OA4MPServiceTransaction.setUsername("FakeUserName");
        String mpUN = "myproxy username /with weird $$#@ in=it/#" + System.nanoTime();
        OA4MPServiceTransaction.setMyproxyUsername(mpUN);
        Client client = (Client) clientStore.create();
        client.setIdentifier(new BasicIdentifier(URI.create("test:client:1d/" + System.currentTimeMillis())));
        OA4MPServiceTransaction.setAuthorizationGrant(newAG(tokenForge));
        OA4MPServiceTransaction.setAuthGrantValid(false);
        client.setName("service test name #" + System.nanoTime());
        transactionStore.save(OA4MPServiceTransaction);
        assert transactionStore.containsKey(OA4MPServiceTransaction.getIdentifier());
        assert OA4MPServiceTransaction.equals(transactionStore.get(OA4MPServiceTransaction.getIdentifier()));
        assert OA4MPServiceTransaction.equals(transactionStore.get(OA4MPServiceTransaction.getAuthorizationGrant()));
        // now emulate doing oauth type transactions with it.
        // First leg sets the verifier and user

        String r = getRandomString(12);
        OA4MPServiceTransaction.setVerifier(newVerifier(tokenForge));
        transactionStore.save(OA4MPServiceTransaction);

        assert OA4MPServiceTransaction.equals(transactionStore.get(OA4MPServiceTransaction.getVerifier()));
        // next leg creates the access tokens and invalidates the temp credentials
        OA4MPServiceTransaction.setAccessToken(newAT(tokenForge));
        OA4MPServiceTransaction.setAuthGrantValid(false);
        OA4MPServiceTransaction.setAccessTokenValid(true);
        transactionStore.save(OA4MPServiceTransaction);
        assert OA4MPServiceTransaction.equals(transactionStore.get(OA4MPServiceTransaction.getIdentifier()));
        assert OA4MPServiceTransaction.equals(transactionStore.get(OA4MPServiceTransaction.getAccessToken()));
        OA4MPServiceTransaction.setAccessTokenValid(false);
        transactionStore.save(OA4MPServiceTransaction);
        assert OA4MPServiceTransaction.equals(transactionStore.get(OA4MPServiceTransaction.getIdentifier()));
        //and we're done
        transactionStore.remove(OA4MPServiceTransaction.getIdentifier());
        assert !transactionStore.containsKey(OA4MPServiceTransaction.getIdentifier());
    }
}
