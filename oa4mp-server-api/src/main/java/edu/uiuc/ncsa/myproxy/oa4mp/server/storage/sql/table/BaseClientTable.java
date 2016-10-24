package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table;

import edu.uiuc.ncsa.security.delegation.storage.BaseClientKeys;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  2:06 PM
 */
public class BaseClientTable extends Table {
    public BaseClientTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    protected BaseClientKeys getBKK(){
        return (BaseClientKeys)keys;
    }
    @Override
       public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(getBKK().secret(), LONGVARCHAR));
    }
}
