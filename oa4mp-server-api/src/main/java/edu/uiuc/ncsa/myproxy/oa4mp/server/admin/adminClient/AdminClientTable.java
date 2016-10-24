package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.BaseClientTable;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  2:03 PM
 */
public class AdminClientTable extends BaseClientTable {
    public AdminClientTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }
}
