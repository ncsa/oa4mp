package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import java.sql.Types;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  4:56 PM
 */
public class JSONStoreSQLTable extends Table {
    public static String DEFAULT_TABLE_NAME = "jsonStore";
    public JSONStoreSQLTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected JSONStoreKeys storeKeys() {
        return (JSONStoreKeys) keys;
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(storeKeys().content(), Types.LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(storeKeys().creationTimpestamp(), Types.TIMESTAMP));

    }
}
