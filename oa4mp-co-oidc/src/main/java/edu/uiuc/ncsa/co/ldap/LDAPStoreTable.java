package edu.uiuc.ncsa.co.ldap;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  4:01 PM
 */
public class LDAPStoreTable extends Table {
    public LDAPStoreTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        LDAPEntryKeys k = (LDAPEntryKeys)keys;
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.clientID(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.ldap(), LONGVARCHAR));
    }
}
