package edu.uiuc.ncsa.co.ldap;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

/**
 * Must have an interface for multi-provider framework to function.
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  3:27 PM
 */
public interface LDAPStore<V extends LDAPEntry> extends Store<V> {
     public LDAPEntry getByClientID(Identifier clientID);

}
