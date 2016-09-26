package edu.uiuc.ncsa.myproxy.oa4mp.file;

import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.TransactionStoreTest;
import edu.uiuc.ncsa.security.storage.FileStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:59 PM
 */
public class FSTransactionStoreTest extends TransactionStoreTest {
    @Override
    protected Class getStoreClass() {
        return FileStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getFsStoreProvider();
    }
}
