package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetSerializationKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import java.sql.Types;

import static java.sql.Types.BIGINT;
import static java.sql.Types.LONGVARCHAR;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  3:14 PM
 */
public class OA2AssetStoreTable extends AssetStoreTable {
    public OA2AssetStoreTable(AssetSerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    OA2AssetSerializationKeys ask() {
        return (OA2AssetSerializationKeys) keys;
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().accessToken(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().refreshToken(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().refreshLifetime(), BIGINT, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().state(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().nonce(), LONGVARCHAR, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().issuedAt(), Types.DATE, true, false));

    }
}
