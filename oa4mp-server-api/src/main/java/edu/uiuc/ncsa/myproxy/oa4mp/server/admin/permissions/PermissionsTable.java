package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.BOOLEAN;
import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/16 at  12:22 PM
 */
public class PermissionsTable extends Table {
    public PermissionsTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected PermissionKeys pk() {
        return (PermissionKeys) keys;
    }

    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().adminID(), LONGVARCHAR, false, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().clientID(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().readable(), BOOLEAN, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().writeable(), BOOLEAN, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().canCreate(), BOOLEAN, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().canRemove(), BOOLEAN, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(pk().canApprove(), BOOLEAN, true, false));

    }
}
