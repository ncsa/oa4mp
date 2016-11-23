package edu.uiuc.ncsa.oauth2.test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

import edu.uiuc.ncsa.myproxy.oa4mp.ServiceConfigTest;
import edu.uiuc.ncsa.myproxy.oa4mp.aggregate.AGCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.aggregate.AGClientTest;
import edu.uiuc.ncsa.myproxy.oa4mp.file.FSCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.file.FSClientTest;
import edu.uiuc.ncsa.myproxy.oa4mp.file.FSTransactionStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.memory.MCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.memory.MClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.memory.MTransactionStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.mysql.MySQLCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.mysql.MySQLClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.mysql.MySQLTransactionStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.myproxy.oa4mp.postgres.PGCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.postgres.PGClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.postgres.PGTransactionStoreTest;
import edu.uiuc.ncsa.security.delegation.storage.FileStoreTest;
import junit.framework.TestSuite;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;


/**
 * <p>Created by Jeff Gaynor<br>
 * on Nov 27, 2010 at  1:28:14 PM
 */
@RunWith(Suite.class)

@Suite.SuiteClasses({
        TokenTest2.class,
        AGClientTest.class,
        AGCAStoreTest.class,
        //     AGTransactionStoreTest.class,
        FSClientTest.class,
        FSCAStoreTest.class,
        FSTransactionStoreTest.class,
        MClientStoreTest.class,
        MCAStoreTest.class,
        MTransactionStoreTest.class,
        MySQLClientStoreTest.class,
        MySQLCAStoreTest.class,
        MySQLTransactionStoreTest.class,
        PGClientStoreTest.class,
        PGCAStoreTest.class,
        PGTransactionStoreTest.class,
        FileStoreTest.class,
        ServiceConfigTest.class,
        RefreshTokenStoreTest.class,
        AdminClientTest.class,
        PermissionTest.class
})
public class ServiceTestSuite2 extends TestSuite {

    @BeforeClass
    public static void initialize() {
        TestSuiteInitializer testSuiteInitializer = new TestSuiteInitializer(new OA2Bootstrapper());
        testSuiteInitializer.init();
    }
}
