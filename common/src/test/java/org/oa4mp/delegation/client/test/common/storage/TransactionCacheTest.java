package org.oa4mp.delegation.client.test.common.storage;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.CachedMapFacade;
import edu.uiuc.ncsa.security.core.cache.CachedObject;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.cache.MaxCacheSizePolicy;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import org.oa4mp.delegation.common.storage.transactions.TransactionCache;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.Verifier;
import org.junit.Test;

import java.net.URI;
import java.util.HashMap;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 4, 2010 at  3:14:34 PM
 */
public class TransactionCacheTest extends BaseTransactionStoreTest {
    @Override
    protected AuthorizationGrant newAG(URI id) {
        return new FileStoreTest.FakeAuthorizationGrant(id.toString());
    }

    @Override
    protected Verifier newVerifier(URI id) {
        return new FileStoreTest.FakeVerifier(id.toString());
    }

    @Override
    protected AccessToken newAT(URI id) {
        return new FileStoreTest.FakeAccessToken(id.toString());
    }

    static TransactionStore transactionStore;

    /**
     * Since this lives in memory only, a single instance must be available to all clients that use it. New instances
     * are always empty!
     *
     * @return
     */
    public TransactionStore<BasicTransaction> getStore() {
        if (transactionStore == null) {
            transactionStore = new TransactionCache();
        }
        return transactionStore;
    }

    public CachedMapFacade getTransactionCache() {
        return (CachedMapFacade) getStore();
    }

    @Test
    public void testCleanup() throws Exception {
        int maxCacheSize = 10;
        Cleanup<Identifier, CachedObject> cc = new Cleanup<Identifier, CachedObject>(new MyLoggingFacade(getClass().getSimpleName()+".testCleanup", true), "test cleanup");
        cc.addRetentionPolicy(new MaxCacheSizePolicy(getTransactionCache().getCache(), maxCacheSize));
        cc.setMap(getTransactionCache().getCache());
        cc.setEnabledLocking(false);
        HashMap<Identifier, Identifiable> hashMap = new HashMap<Identifier, Identifiable>();
        for (int i = 0; i < maxCacheSize + 5; i++) {
            BasicTransaction bt =  getStore().create();
            bt.setAuthorizationGrant(newAG(URI.create("foo:bar" + i + "/baz" + System.currentTimeMillis())));
            hashMap.put(bt.getIdentifier(), bt);
            getStore().put(bt.getIdentifier(), bt);
            getStore().save(bt);
        }
        cc.age();
        assert maxCacheSize == cc.getMap().size();
    }

}
