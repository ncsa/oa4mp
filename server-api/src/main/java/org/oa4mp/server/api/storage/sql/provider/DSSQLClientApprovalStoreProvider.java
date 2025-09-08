package org.oa4mp.server.api.storage.sql.provider;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import org.oa4mp.server.api.ClientApprovalProvider;
import org.oa4mp.server.api.OA4MPConfigTags;
import org.oa4mp.server.api.storage.sql.SQLClientApprovalStore;
import org.oa4mp.server.api.storage.sql.table.ClientApprovalTable;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/12 at  3:47 PM
 */
public class DSSQLClientApprovalStoreProvider extends SQLStoreProvider<SQLClientApprovalStore> implements OA4MPConfigTags {

    public DSSQLClientApprovalStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            String target,
            String tablename,
            MapConverter converter) {
        super(config, cpp, type, target, tablename, converter);
    }
    public DSSQLClientApprovalStoreProvider(
            CFNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp,
            String type,
            String target,
            String tablename,
            MapConverter converter) {
        super(config, cpp, type, target, tablename, converter);
    }

    public DSSQLClientApprovalStoreProvider(
            ConfigurationNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp, String type, MapConverter converter) {
        super(config, cpp, type, OA4MPConfigTags.CLIENT_APPROVAL_STORE, SQLClientApprovalStore.DEFAULT_TABLENAME, converter);
    }
    public DSSQLClientApprovalStoreProvider(
            CFNode config,
            ConnectionPoolProvider<? extends ConnectionPool> cpp, String type, MapConverter converter) {
        super(config, cpp, type, OA4MPConfigTags.CLIENT_APPROVAL_STORE, SQLClientApprovalStore.DEFAULT_TABLENAME, converter);
    }


    @Override
    public SQLClientApprovalStore newInstance(Table table) {
        return new SQLClientApprovalStore(getConnectionPool(), table, new ClientApprovalProvider(), converter);
    }


    @Override
    public SQLClientApprovalStore get() {
        ClientApprovalTable cat = new ClientApprovalTable(
                (ClientApprovalKeys) converter.keys,
                getSchema(),
                getPrefix(),
                getTablename());
        return newInstance(cat);
    }
}
