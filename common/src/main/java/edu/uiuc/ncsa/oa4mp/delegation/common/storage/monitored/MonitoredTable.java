package edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored;

import edu.uiuc.ncsa.security.storage.data.MonitoredKeys;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.BIGINT;
import static java.sql.Types.TIMESTAMP;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/29/23 at  11:28 AM
 */
public class MonitoredTable extends Table {
    public MonitoredTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected MonitoredKeys getKeys(){
        return (MonitoredKeys) keys;
    }
    public void createColumnDescriptors(){
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().lastAccessed(), BIGINT, false, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().lastModifiedTS(), TIMESTAMP, false, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().creationTS(), TIMESTAMP, false, false));
    }

}
