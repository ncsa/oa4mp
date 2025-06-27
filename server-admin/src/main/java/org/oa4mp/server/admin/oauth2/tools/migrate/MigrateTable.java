package org.oa4mp.server.admin.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/24 at  7:18 AM
 */
public class MigrateTable extends Table {
    public MigrateTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
    protected MigrateKeys getKeys(){
        return (MigrateKeys) super.keys;
    }
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().create_ts(),TIMESTAMP,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().import_ts(),TIMESTAMP,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().error_message(),CLOB,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().store_type(),LONGVARCHAR,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().path(),LONGVARCHAR,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().is_imported(),BOOLEAN,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().import_code(),BOOLEAN,false,false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().filename(),LONGVARCHAR,false,false));


    }

    /*
     public void createColumnDescriptors(){
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().lastAccessed(), BIGINT, false, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().lastModifiedTS(), TIMESTAMP, false, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(getKeys().creationTS(), TIMESTAMP, false, false));
    }

    /*
    CREATE TABLE oauth2.migrate
    (
       create_ts              timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
       import_ts              timestamp,
       id                     varchar(255),
       store_type             varchar(255),
       path                   varchar(255),
       is_imported            boolean,
       import_ok              boolean,
       error_message          clob,
       filename               VARCHAR(255) PRIMARY KEY
    );*/
}
