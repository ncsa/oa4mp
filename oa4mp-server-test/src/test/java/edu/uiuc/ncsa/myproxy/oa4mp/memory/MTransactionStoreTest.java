package edu.uiuc.ncsa.myproxy.oa4mp.memory;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.TransactionStoreTest;
import edu.uiuc.ncsa.security.storage.MemoryStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:59 PM
 */
public class MTransactionStoreTest extends TransactionStoreTest {
    @Override
    protected Class getStoreClass() {
        return MemoryStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getMemoryStoreProvider();
    }
}
