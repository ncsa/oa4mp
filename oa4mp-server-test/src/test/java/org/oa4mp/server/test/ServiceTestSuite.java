package org.oa4mp.server.test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

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
    //    TokenTest.class,
   //     TransactionStoreTest.class,
    //    ClientStoreTest.class,
      //  ServiceConfigTest.class
        JFunctorTest.class,
        JFunctorFactoryTests.class
})
public class ServiceTestSuite extends TestSuite {
    @BeforeClass
    public static void initialize() {

    }
}
