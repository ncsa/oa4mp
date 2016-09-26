package edu.uiuc.ncsa.myproxy.oa4mp;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

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
        TokenTest.class,
        TransactionStoreTest.class,
        ClientStoreTest.class,
        ServiceConfigTest.class
})
public class ServiceTestSuite extends TestSuite {
    @BeforeClass
    public static void initialize() {

    }
}
