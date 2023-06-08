package edu.uiuc.ncsa.oa4mp.delegation.server.storage.support;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.BasicTransactionTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import static java.sql.Types.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2010 at  2:08:12 PM
 */
public abstract class ServiceTransactionTable extends BasicTransactionTable {

    /**
     * The schema and prefix are not part of the table's information, actually, but are needed to
     * create its fully qualified name in context. Hence they must be supplied.
     *
     * @param schema
     * @param tablenamePrefix
     */
    public ServiceTransactionTable(ServiceTransactionKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        ServiceTransactionKeys x = (ServiceTransactionKeys)keys;
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.tempCredValid(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.accessTokenValid(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.callbackUri(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(x.lifetime(), BIGINT, true, false));
    }
}
