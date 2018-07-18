package test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

import edu.uiuc.ncsa.myproxy.oa4mp.NewCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.NewClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.NewTransactionTest;
import edu.uiuc.ncsa.myproxy.oa4mp.ServiceConfigTest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader.COBootstrapper;
import edu.uiuc.ncsa.security.delegation.storage.FileStoreTest;
import edu.uiuc.ncsa.security.util.JFunctorFactoryTests;
import edu.uiuc.ncsa.security.util.JFunctorTest;
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
        JFunctorTest.class,
        OA2ParserTest.class,
        JFunctorFactoryTests.class,
        NewCAStoreTest.class,
        NewClientStoreTest.class,
        NewTransactionTest.class,
        ClientManagerTest.class,
        AttributeServerTest.class,
        PermissionServerTest.class,
        ClientServerTest.class,
        TokenTest2.class,
        FileStoreTest.class,
        ServiceConfigTest.class,
        RefreshTokenStoreTest.class,
        AdminClientTest.class,
        PermissionTest.class
})
public class ServiceTestSuite2 extends TestSuite {

    @BeforeClass
    public static void initialize() {
    /*    TestSuiteInitializer testSuiteInitializer = new TestSuiteInitializer(new OA2Bootstrapper());
        testSuiteInitializer.init();*/
        TestSuiteInitializer testSuiteInitializer = new CMTestSuiteInitializer(new COBootstrapper());
        testSuiteInitializer.init();
    }
}
