package edu.uiuc.ncsa.myproxy.oa4mp.postgres;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.TransactionStoreTest;
import edu.uiuc.ncsa.security.delegation.storage.impl.SQLBaseTransactionStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:59 PM
 */
public class PGTransactionStoreTest extends TransactionStoreTest {
    @Override
    protected Class getStoreClass() {
        return SQLBaseTransactionStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getPgStoreProvider();
    }
}
