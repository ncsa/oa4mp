package org.oa4mp.delegation.client.test.common.storage;

import edu.uiuc.ncsa.security.core.Initializable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.util.TestBase;
import org.junit.Test;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 4, 2010 at  3:20:20 PM
 */
public abstract class BaseTransactionStoreTest extends TestBase {

    abstract protected AuthorizationGrant newAG(URI id);

    protected AuthorizationGrant newAG() {
        return newAG(createToken("authorizationGrant"));
    }


    abstract protected AccessToken newAT(URI id);

    protected AccessToken newAT() {
        return newAT(createToken("accessToken"));
    }

    public abstract TransactionStore<? extends BasicTransaction> getStore() throws Exception;

    public TransactionStore getInitializedStore() throws Exception {
        TransactionStore store = getStore();
        if (store instanceof Initializable) {
            Initializable initializable = (Initializable) store;
            if (!initializable.isCreated()) {
                initializable.createNew();
            }
            if (!initializable.isInitialized()) {
                initializable.init();
            }
        }
        return store;
    }

    protected BasicTransaction createTransaction(TransactionStore store) {
        String identifier = "urn:test:identifier/" + getRandomString() + "/" + System.currentTimeMillis();
        FileStoreTest.FakeAuthorizationGrant fag = new FileStoreTest.FakeAuthorizationGrant(identifier);

        BasicTransaction t = (BasicTransaction) store.create();
        t.setAuthorizationGrant(fag);
        return t;
    }

    @Test
    public void testInitializable() throws Exception {

        TransactionStore store = getStore();
        if (!(store instanceof Initializable)) {
            assert true;
            return;
        }
        // Test the contract for initializable stores.
        Initializable initializable = (Initializable) store;
        // test assures that store is new.
        if (!initializable.isCreated()) {
            initializable.createNew();
        }

        if (!initializable.isInitialized()) {
            initializable.init();
        }
        // should be able to put stuff in it, so
        String identifier = "urn:test:identifier/" + getRandom();

        BasicTransaction t = (BasicTransaction) store.create();
        t.setAuthorizationGrant(newAG());
        // now we initialize it and check that there is nothing in it.
        initializable.init();
        assert !store.containsValue(t);

        // put it back in
        t = (BasicTransaction) store.create();
        t.setAuthorizationGrant(newAG());
        initializable.destroy();

        assert !initializable.isCreated();

    }


    @Test
    public void testStore() throws Exception {
        TransactionStore store = getInitializedStore();

        AccessToken at = newAT();
        BasicTransaction t = createTransaction(store);
        t.setAccessToken(at);

        AuthorizationGrant ag = t.getAuthorizationGrant(); // this is set in the call above.

        store.save(t);
        BasicTransaction t2 = (BasicTransaction) store.get(t.getIdentifier());
        assert t2 != null : "Could not save file for id=\"" + t.getIdentifierString() + "\"";
        assert t.equals(t2);
        assert t.equals(store.get(ag));
        assert t.equals(store.get(at));

        // now repeat it, clearing out the store each time.
        store = getStore();

        assert t.equals(store.get(ag));

        store = getStore();
        assert t.equals(store.get(at));

        assert store.get(newAG(createToken("fake"))) == null;
    }

    /**
     * Some stores -- such as large databases, should not have the values() call in the map
     * interface tested on them since the overhead is huge and the it takes forever. If this
     * is over-ridden to return false, those tests will be skipped.
     *
     * @return
     */
    public boolean testMapAllValues() {
        return true;
    }

    @Test
    public void testMap() throws Exception {
        TransactionStore store = getInitializedStore();
        BasicTransaction t = (BasicTransaction) store.create();
        AuthorizationGrant ag = newAG();
        t.setAuthorizationGrant(ag);
        // creating does not persist
        assert null == store.get(BasicIdentifier.newID(ag.getToken()));


        // Failure modes
        try {
            //updating a non-existent transaction fails
            store.update(t);
            assert false : " was able to update an non-existent transaction";
        } catch (GeneralException x) {
            assert true;
        }
        // Make another transaction to compare with the first

        ag = newAG();
        AccessToken at = newAT();

        t.setAuthorizationGrant(ag);
        t.setAccessToken(at);


        int beforeSaveSize = store.size();
        store.save(t);
        assert beforeSaveSize + 1 == store.size();

        assert !store.isEmpty();
        assert store.containsValue(t);
        assert store.containsKey(t.getIdentifier());

        t.setAccessToken(at);
        //store.put(t.getIdentifier(), t);
        store.save( t);
        // Check it gets stored right, then retrieve it.


        assert t.equals(store.get(t.getIdentifier()));

        store.remove(t.getIdentifier());
        if (testMapAllValues()) {
            assert beforeSaveSize == store.keySet().size();
            assert store.keySet().size() == beforeSaveSize;
            assert store.values().size() == beforeSaveSize;
            assert store.entrySet().size() == beforeSaveSize;
        }
    }
}
