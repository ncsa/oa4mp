package org.oa4mp.server.loader.oauth2.storage.vo;

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
    protected VISerializationKeys vok(){return (VISerializationKeys) keys;}

    @Override
      public void createColumnDescriptors() {
        /*
         Note that this does not extend MonitoredTable since the backend types for last modified
         and created were longs, not dates. We do not want to force existing installs to completly
         change.
         */
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().atIssuer(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().creationTS(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().defaultKeyID(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().discoveryPath(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().issuer(), java.sql.Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().jsonWebKeys(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().lastAccessed(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().lastModifiedTS(), Types.BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().title(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(vok().valid(), Types.BOOLEAN));
    }
}
