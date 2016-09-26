package edu.uiuc.ncsa.myproxy.oa4mp;


import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import org.junit.Test;

import java.net.URI;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 19, 2011 at  12:03:54 PM
 */
public abstract class TransactionStoreTest extends StoreTest{

    @Override
    public void checkStoreClass() throws Exception {
         testClassAsignability(getStore());
    }

    public TransactionStore getStore() throws Exception {
        return getTSProvider().getTransactionStore();
    }

    protected AuthorizationGrant newAG(String... x) {
        AuthorizationGrant ag = getTSProvider().getTokenForge().getAuthorizationGrant(x);
        // The forge may return a shared secret. Since we never use this in OA4MP, make sure it is null
        // or you will get false test results since the secret won't be stored.
        ag.setSharedSecret(null);
        return ag;
    }

    protected Verifier newVerifier(String... x) {
       return getTSProvider().getTokenForge().getVerifier(x);
    }

    protected AccessToken newAT(String... x) {
        AccessToken  at = getTSProvider().getTokenForge().getAccessToken(x);
        at.setSharedSecret(null);
        return at;
    }

    @Test
    public void testServiceTransaction() throws Exception {
        OA4MPServiceTransaction OA4MPServiceTransaction = (OA4MPServiceTransaction) getStore().create();
        OA4MPServiceTransaction.setCallback(URI.create("http://callback"));

        OA4MPServiceTransaction.setLifetime(10 * 60 * 60 * 1000); // set lifetime to 10 hours (stored in ms!)
        OA4MPServiceTransaction.setUsername("FakeUserName");
        String mpUN = "myproxy username /with weird $$#@ in=it/#" + System.nanoTime();
        OA4MPServiceTransaction.setMyproxyUsername(mpUN);
        Client client = getTSProvider().getClientStore().create();
        client.setIdentifier(new BasicIdentifier(URI.create("test:client:1d/" + System.currentTimeMillis())));
        OA4MPServiceTransaction.setAuthorizationGrant(newAG());
        OA4MPServiceTransaction.setAuthGrantValid(false);
        client.setName("service test name #" + System.nanoTime());
        getStore().save(OA4MPServiceTransaction);
        assert getStore().containsKey(OA4MPServiceTransaction.getIdentifier());
        assert OA4MPServiceTransaction.equals(getStore().get(OA4MPServiceTransaction.getIdentifier()));
        assert OA4MPServiceTransaction.equals(getStore().get(OA4MPServiceTransaction.getAuthorizationGrant()));
        // now emulate doing oauth type transactions with it.
        // First leg sets the verifier and user

        String r = getRandomString(12);
        OA4MPServiceTransaction.setVerifier(newVerifier());
        getStore().save(OA4MPServiceTransaction);

        assert OA4MPServiceTransaction.equals(getStore().get(OA4MPServiceTransaction.getVerifier()));
        // next leg creates the access tokens and invalidates the temp credentials
        OA4MPServiceTransaction.setAccessToken(newAT());
        OA4MPServiceTransaction.setAuthGrantValid(false);
        OA4MPServiceTransaction.setAccessTokenValid(true);
        getStore().save(OA4MPServiceTransaction);
        assert OA4MPServiceTransaction.equals(getStore().get(OA4MPServiceTransaction.getIdentifier()));
        assert OA4MPServiceTransaction.equals(getStore().get(OA4MPServiceTransaction.getAccessToken()));
        OA4MPServiceTransaction.setAccessTokenValid(false);
        getStore().save(OA4MPServiceTransaction);
        assert OA4MPServiceTransaction.equals(getStore().get(OA4MPServiceTransaction.getIdentifier()));
        //and we're done
        getStore().remove(OA4MPServiceTransaction.getIdentifier());
        assert !getStore().containsKey(OA4MPServiceTransaction.getIdentifier());
    }
}
