package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientStoreTable;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ClientKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import static java.sql.Types.BIGINT;
import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/14 at  1:31 PM
 */
public class OA2ClientTable extends ClientStoreTable {
    public OA2ClientTable(OA2ClientKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        OA2ClientKeys k = (OA2ClientKeys)keys;
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.callbackUri(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.rtLifetime(), BIGINT));
    }
}
