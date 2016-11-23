package edu.uiuc.ncsa.co;

import edu.uiuc.ncsa.co.ldap.LDAPStore;
import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.oauth2.test.TestStoreProvider2;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  12:26 PM
 */
public abstract class CMTestStoreProvider extends TestStoreProvider2 {
    protected COSE getCOSE(){return (COSE) getSE();}

    public LDAPStore getLDAPStore(){
        return getCOSE().getLDAPStore();
    }

}
