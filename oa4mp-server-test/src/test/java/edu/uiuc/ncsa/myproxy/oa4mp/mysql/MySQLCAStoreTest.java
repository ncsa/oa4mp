package edu.uiuc.ncsa.myproxy.oa4mp.mysql;

import edu.uiuc.ncsa.myproxy.oa4mp.CAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientApprovalStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:58 PM
 */
public class MySQLCAStoreTest extends CAStoreTest {
    @Override
    protected Class getStoreClass() {
        return SQLClientApprovalStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getMySQLStoreProvider();
    }
}
