package edu.uiuc.ncsa.co.ldap;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  9:30 AM
 */
public class LDAPEntryProvider<V extends LDAPEntry> extends IdentifiableProviderImpl<V> {
    public static final String LDAP_ENTRY_ID = "ldapConfiguration";

    public LDAPEntryProvider() {
        super(new OA4MPIdentifierProvider(LDAP_ENTRY_ID));
    }

    @Override
    public V get(boolean createNewIdentifier) {
        return (V) new LDAPEntry(createNewId(createNewIdentifier));
    }
}
