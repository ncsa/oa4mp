package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientStoreTable;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnDescriptorEntry;

import static java.sql.Types.*;

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
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.scopes(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.audience(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.dfLifetime(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.dfInterval(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.rtLifetime(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.atLifetime(), BIGINT));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.issuer(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.ldap(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.cfg(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.ea(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.signTokens(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.proxyClaimsList(), LONGVARCHAR));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.publicClient(), BOOLEAN));
        getColumnDescriptor().add(new ColumnDescriptorEntry(k.strictScopes(), BOOLEAN));
    }
}
