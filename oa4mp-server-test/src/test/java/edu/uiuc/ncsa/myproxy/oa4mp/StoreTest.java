package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.util.TestBase;
import org.junit.Test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:08 PM
 */
public abstract class StoreTest extends TestBase implements StoreProvidable {
    protected abstract Class getStoreClass();

    @Test
    public abstract void checkStoreClass() throws Exception;

      protected void testClassAsignability(Store store){
        assert getStoreClass().isAssignableFrom(store.getClass()) : "The store is not of type " + getStoreClass().getSimpleName();
    }
}
