package edu.uiuc.ncsa.myproxy.oa4mp.aggregate;

import edu.uiuc.ncsa.myproxy.oa4mp.CAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.security.storage.AggregateStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:58 PM
 */
public class AGCAStoreTest extends CAStoreTest {
    @Override
    protected Class getStoreClass() {
        return AggregateStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getAgStoreProvider();
    }
}
