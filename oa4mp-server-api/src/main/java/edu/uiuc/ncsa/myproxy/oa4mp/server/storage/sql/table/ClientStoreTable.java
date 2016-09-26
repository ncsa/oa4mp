package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table;

import edu.uiuc.ncsa.security.delegation.storage.ClientKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 24, 2011 at  11:10:02 AM
 */
public class ClientStoreTable extends Table {


    /**
     * The schema and prefix are not part of the table's information, actually, but are needed to
     * create its fully qualified name in context. Hence they must be supplied.
     *
     * @param schema
     * @param tablenamePrefix
     */
    public ClientStoreTable(ClientKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    ClientKeys ct() {return (ClientKeys)keys;}
    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().secret(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().name(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().homeURL(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().errorURL(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().email(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().creationTS(), TIMESTAMP));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ct().proxyLimited(), BOOLEAN));
    }
}
