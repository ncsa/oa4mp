package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import java.sql.Types;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:22 AM
 */
public class TXRecordTable extends Table {
    public TXRecordTable(TXRecordSerializationKeys keys,
                         String schema,
                         String tablenamePrefix,
                         String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
    protected TXRecordSerializationKeys tkeys(){
         return (TXRecordSerializationKeys) keys;
     }

    @Override
      public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().audience(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().isValid(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().expiresAt(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().lifetime(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().issuedAt(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().resource(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().issuer(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().scopes(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().parentID(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(tkeys().tokenType(), Types.LONGVARCHAR));
    }

    public String getSearchByParentIDStatement(){
        return "select * from " + getFQTablename() + " where " + tkeys().parentID + " = ?";
    }

    public String getCountByParentIDStatement(){
        return "select count(*) from " + getFQTablename() + " where " + tkeys().parentID + " = ?";
    }
}
