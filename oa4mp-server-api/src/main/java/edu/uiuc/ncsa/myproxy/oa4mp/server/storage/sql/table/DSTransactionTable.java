package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.keys.DSTransactionKeys;
import edu.uiuc.ncsa.security.delegation.server.storage.support.ServiceTransactionTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 19, 2011 at  10:18:00 AM
 */
public class DSTransactionTable extends ServiceTransactionTable {
    /**
     * The schema and prefix are not part of the table's information, actually, but are needed to
     * create its fully qualified name in context. Hence they must be supplied.
     *
     * @param schema
     * @param tablenamePrefix
     */
    public DSTransactionTable(DSTransactionKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        DSTransactionKeys x = (DSTransactionKeys)keys;
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.certReq(), LONGVARCHAR)); //as per spec
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.cert(), LONGVARCHAR)); // as per spec
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.clientKey(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.username(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.myproxyUsername(), LONGVARCHAR, true, false));
    }
}
