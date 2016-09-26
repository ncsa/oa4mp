package edu.uiuc.ncsa.myproxy.oa4mp.mysql;

import edu.uiuc.ncsa.myproxy.oa4mp.ClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientStore;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:57 PM
 */
public class MySQLClientStoreTest extends ClientStoreTest {
    @Override
    protected Class getStoreClass() {
        return SQLClientStore.class;
    }

    @Override
    public TestStoreProvider getTSProvider() {
        return TestUtils.getMySQLStoreProvider();
    }
}
