package org.oa4mp.client.loader;

import org.oa4mp.client.api.storage.AssetSerializationKeys;
import org.oa4mp.client.api.storage.AssetStoreTable;
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
        // CIL-1608
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().idToken(), LONGVARCHAR, true, false));
        // https://github.com/rcauth-eu/OA4MP/commit/83472a5c65dbe3784d48d73433e207601c73ce52
        //getColumnDescriptor().add(new ColumnDescriptorEntry(ask().issuedAt(), Types.DATE, true, false));
        getColumnDescriptor().add(new ColumnDescriptorEntry(ask().issuedAt(), Types.TIMESTAMP, true, false));
    }
}
