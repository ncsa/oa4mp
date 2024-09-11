package org.oa4mp.delegation.client.test.common.storage;

import junit.framework.TestSuite;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Nov 27, 2010 at  1:23:49 PM
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({TransactionCacheTest.class,
        FileStoreTest.class})
public class TransactionTestSuite extends TestSuite {
}
