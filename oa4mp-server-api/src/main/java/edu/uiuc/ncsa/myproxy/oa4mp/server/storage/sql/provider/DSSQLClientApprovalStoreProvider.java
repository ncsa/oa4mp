package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.provider;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.SQLClientApprovalStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientApprovalTable;
import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPoolProvider;
import edu.uiuc.ncsa.security.storage.sql.SQLStoreProvider;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.apache.commons.configuration.tree.ConfigurationNode;

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
            ConfigurationNode config,
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
