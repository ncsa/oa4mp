package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap.LDAPStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader.COSE;

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
