package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table;

import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 26, 2011 at  9:41:59 AM
 */
public class ClientApprovalTable extends Table {

    /**
     * The schema and prefix are not part of the table's information, actually, but are needed to
     * create its fully qualified name in context. Hence they must be supplied.
     *
     * @param schema
     * @param tablenamePrefix
     */
    public ClientApprovalTable(ClientApprovalKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    public ClientApprovalKeys ca() {
        return (ClientApprovalKeys) keys;
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(ca().approver(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ca().approvalTS(), TIMESTAMP));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ca().approved(), BOOLEAN));
    }
}
