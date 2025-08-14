package org.oa4mp.server.api.storage.sql.table;

import org.oa4mp.delegation.common.storage.clients.BaseClientKeys;
import org.oa4mp.delegation.common.storage.monitored.MonitoredTable;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import static java.sql.Types.BOOLEAN;
import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  2:06 PM
 */
public  class BaseClientTable extends MonitoredTable {
    public BaseClientTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    protected BaseClientKeys getKeys() {
        return (BaseClientKeys) super.getKeys();
    }

    @Override
       public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().secret(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().debugOn(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().jwks(), LONGVARCHAR)); // RFC 7523 support
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().rfc7523Client(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().rfc7523ClientUsers(), LONGVARCHAR));

    }


}
