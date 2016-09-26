package edu.uiuc.ncsa.myproxy.oa4mp.aggregate;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.TransactionStoreTest;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.delegation.storage.AggregateTransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.BasicTransaction;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import edu.uiuc.ncsa.security.storage.AggregateStore;
import org.junit.Test;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:59 PM
 */
public class AGTransactionStoreTest extends TransactionStoreTest {
    @Override
    protected Class getStoreClass() {
        return AggregateStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getAgStoreProvider();
    }

    /**
     * This test creates a transaction and does various operations to show that the aggregation actually works
     * as advertised. This tests functionality of the aggregation <b>not</b> transactions per se, so even though
     * it uses transactions, it is a generic test.
     *
     * @throws Exception
     */
    @Test
    public void testAggregation() throws Exception {
        AggregateTransactionStore atStore = (AggregateTransactionStore) TestUtils.getAgStoreProvider().getTransactionStore();
        List<Store> allStores = atStore.stores();
        assert 1 < allStores.size() : "Configuration error: There is only a single store in the aggregate. There must be at least 2.";
        TransactionStore<BasicTransaction> defaultStore = (TransactionStore) atStore.defaultStore();
        TransactionStore<BasicTransaction> lastStore = (TransactionStore) allStores.get(allStores.size() - 1);
        BasicTransaction t = lastStore.create();
        AuthorizationGrant ag = getTSProvider().getTokenForge().getAuthorizationGrant();
        Verifier v = getTSProvider().getTokenForge().getVerifier();
        AccessToken at = getTSProvider().getTokenForge().getAccessToken();

        //NOTE that since RSH-SHA1 is used for OA4MP protocol, equality will later fail
        // for tests involving authz grants and access tokens. Shared secrets are
        // required only for the CILogon 1 protocol.
        ag.setSharedSecret(null);
        at.setSharedSecret(null);
        t.setAuthorizationGrant(ag); // lets us set the identifier too for later use.
        lastStore.save(t);
        // see that the a store finds it.
        // check that the update is only in the last store.
        assert lastStore.containsKey(t.getIdentifier());
        assert !defaultStore.containsKey(t.getIdentifier());

        t.setVerifier(v);
        t.setAccessToken(at);
        // Now update this through the aggregate. Expected behavior is that only the last store gets changed.
        atStore.update(t);

        assert lastStore.get(t.getIdentifier()).getVerifier().equals(v);

        // make sure it is recoverable by other keys.
        assert atStore.get(v).equals(t);
        assert atStore.get(t.getAuthorizationGrant()).equals(t);
        assert atStore.get(t.getAccessToken()).equals(t);

        // Be darned sure we aren't getting spare copies elsewhere.
        for (int i = 0; i < allStores.size() - 1; i++) {
            TransactionStore transactionStore = (TransactionStore) allStores.get(i);
            assert transactionStore.get(t.getIdentifier()) == null : "Error: transaction was saved in an incorrect store of the aggregate";
            assert transactionStore.get(v) == null : "Error: should not have been able to get a transaction from the default store keyed by verifier";
            assert transactionStore.get(at) == null : "Error: should not have been able to get a transaction from the default store keyed by access token";
            assert transactionStore.get(ag) == null : "Error: should not have been able to get a transaction from the default store keyed by authz grant";
        }
        // now check that a completely new item ends up being created in the first store which is the default.

        BasicTransaction t2 = (BasicTransaction) atStore.create();
        ag = getTSProvider().getTokenForge().getAuthorizationGrant();
        v = getTSProvider().getTokenForge().getVerifier();
        at = getTSProvider().getTokenForge().getAccessToken();

        //NOTE that since RSH-SHA1 is used for OA4MP protocol, equality will later fail
        // for tests involving authz grants and access tokens. Shared secrets are
        // required only for the CILogon 1 protocol.
        ag.setSharedSecret(null);
        at.setSharedSecret(null);
        t2.setAuthorizationGrant(ag);
        t2.setAccessToken(at);
        t2.setVerifier(v);
        atStore.save(t2);

        for (int i = 1; i < allStores.size(); i++) {
            TransactionStore transactionStore = (TransactionStore) allStores.get(i);
            assert transactionStore.get(t2.getIdentifier()) == null : "Error: transaction was saved in an incorrect store of the aggregate";
            assert transactionStore.get(v) == null : "Error: should not have been able to get a transaction keyed by verifier";
            assert transactionStore.get(at) == null : "Error: should not have been able to get a transaction keyed by access token";
            assert transactionStore.get(ag) == null : "Error: should not have been able to get a transaction keyed by authz grant";
        }

    }
}
