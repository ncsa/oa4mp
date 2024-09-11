package test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

import org.oa4mp.server.loader.oauth2.loader.OA2Bootstrapper;
import org.oa4mp.delegation.client.test.common.storage.FileStoreTest;
import edu.uiuc.ncsa.security.core.configuration.ConfigInheritanceTest;
import edu.uiuc.ncsa.security.core.configuration.MultipleInheritanceTest;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionParameters;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.util.*;
import edu.uiuc.ncsa.security.util.cache.CacheTest;
import junit.framework.TestSuite;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.oa4mp.server.test.*;

import java.io.File;

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
        //ClientManagerTest.class,
        //AttributeServerTest.class,
        PermissionServerTest.class,
        //ClientServerTest.class,
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
        System.setProperty(OA2Bootstrapper.OA2_CONFIG_FILE_KEY, DebugUtil.getConfigPath()+"/servers.xml");
        TestSuiteInitializer testSuiteInitializer = new TestSuiteInitializer(new OA2Bootstrapper());
        testSuiteInitializer.init();
        // shutdown hook always works. @AfterClass not so much...
        Runtime.getRuntime().addShutdownHook(new Thread(() -> shutdown()));
    }

    public static void shutdown(){
        try {
            if (TestUtils.getFsStoreProvider().getClientStore() instanceof SQLStore) {
                 SQLStore sqlStore = (SQLStore) TestUtils.getFsStoreProvider().getClientStore();
                 // cleans up the derby file store. Part of the test is re-creating it.
                 if(sqlStore.getConnectionPool().getConnectionParameters() instanceof DerbyConnectionParameters){
                     DerbyConnectionPool derbyConnectionPool = (DerbyConnectionPool)sqlStore.getConnectionPool();
                     derbyConnectionPool.shutdown();
                     DerbyConnectionParameters derbyConnectionParameters = derbyConnectionPool.getConnectionParameters();
                     File f = new File(derbyConnectionParameters.getDatabaseName());
                     // This will recursively remove the entire derby database from the system. 
                     if(f.exists() && f.isDirectory()){
                    //     nuke(f);
                     }
                 }

            }
        }catch(Throwable t){
            t.printStackTrace();
        }
    }

    protected static void nuke(File dir){
        for(File r : dir.listFiles()){
            if(r.isDirectory()){
                nuke(r);
            }
                r.delete(); // directory should be empty, so delete it.
        }
    }
}



