package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;
import org.oa4mp.delegation.common.storage.monitored.MonitoredTable;

import static java.sql.Types.*;

public class KEStoreTable extends MonitoredTable {
    public KEStoreTable(SerializationKeys keys, String schema, String tablenamePrefix, String tablename) {
        super(keys, schema, tablenamePrefix, tablename);
    }

    @Override
    public void createColumnDescriptors() {
        super.createColumnDescriptors();
        KESerializationKeys k = (KESerializationKeys)keys;
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.alg(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.isValid(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.exp(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.iat(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.is_default(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.jwk(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.kid(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.kty(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.nbf(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.use(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.vi(), LONGVARCHAR));

    }
    /*
        protected String alg = "alg";
    protected String archvied = "archvied";
    protected String exp = "exp";
    protected String iat = "iat";
    protected String is_default = "is_default";
    protected String key = "key";
    protected String kid = "kid";
    protected String kty = "kty";
    protected String nbf = "nbf";
    protected String use = "use";
    protected String vi = "vi";
     */
}
