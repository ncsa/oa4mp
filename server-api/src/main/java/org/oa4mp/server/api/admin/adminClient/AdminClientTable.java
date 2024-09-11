package org.oa4mp.server.api.admin.adminClient;

import org.oa4mp.server.api.storage.sql.table.BaseClientTable;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import java.sql.Types;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  2:03 PM
 */
public class AdminClientTable extends BaseClientTable {
    public AdminClientTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected AdminClientKeys ak(){return (AdminClientKeys) keys;}
    @Override
    public void createColumnDescriptors() {

        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().name(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().issuer(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().vo(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().voURI(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().email(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().config(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().maxClients(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().allowQDL(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().notifyOnNewClientCreate(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().listUsers(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().generateIDs(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().allowCustomIDs(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().useTimestampsInIds(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().idHead(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().listUsersInOtherClients(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ak().creationTS(), Types.TIMESTAMP));
    }
}
