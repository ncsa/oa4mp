package test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

import edu.uiuc.ncsa.myproxy.oa4mp.NewCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.NewClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.NewTransactionTest;
import edu.uiuc.ncsa.myproxy.oa4mp.ServiceConfigTest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.security.core.configuration.ConfigInheritanceTest;
import edu.uiuc.ncsa.security.core.configuration.MultipleInheritanceTest;
import edu.uiuc.ncsa.security.delegation.storage.FileStoreTest;
import edu.uiuc.ncsa.security.util.*;
import edu.uiuc.ncsa.security.util.cache.CacheTest;
import junit.framework.TestSuite;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Nov 27, 2010 at  1:28:14 PM
 */
@RunWith(Suite.class)
// start with legacy tests from the security library so we make sure these work.

// Then start the tests for OA4MP proper.

@Suite.SuiteClasses({
        QDLTests.class,
        MultipleInheritanceTest.class,
        ConfigInheritanceTest.class,
        TemplateTest.class,
        CacheTest.class,
        EditorTest.class,
        JSONPreprocessorTest.class,
        JFunctorTest.class,
        ClientConfigurationTest.class,
        OA2ParserTest.class,
        OA2FunctorTests.class,
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
        System.setProperty(OA2Bootstrapper.OA2_CONFIG_FILE_KEY, "/home/ncsa/dev/csd/config/servers.xml");
        TestSuiteInitializer testSuiteInitializer = new TestSuiteInitializer(new OA2Bootstrapper());
        testSuiteInitializer.init();
    }
}



