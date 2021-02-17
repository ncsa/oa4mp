package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import java.sql.Types;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/21 at  9:05 AM
 */
public class VOTable extends Table {
    public VOTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
    protected VOSerializationKeys vok(){return (VOSerializationKeys) keys;}

    @Override
      public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().created(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().defaultKeyID(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().issuer(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().discoveryPath(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().lastModified(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().valid(), Types.BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().jsonWebKeys(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().title(), Types.LONGVARCHAR));
    }
}
