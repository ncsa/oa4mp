package org.oa4mp.server.api.storage.sql;

import org.oa4mp.server.api.ServiceEnvironment;
import org.oa4mp.server.api.admin.permissions.PermissionKeys;
import org.oa4mp.server.api.admin.permissions.SQLPermissionStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.BaseClientSQLStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.cli.StoreArchiver;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConstants;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  4:37:15 PM
 */
public class SQLClientStore<V extends Client> extends BaseClientSQLStore<V> implements ClientStore<V> {
    public static final String DEFAULT_TABLENAME = "clients";


    public SQLClientStore(ConnectionPool connectionPool,
                          Table table,
                          Provider<V> idp,
                          MapConverter converter
    ) {
        super(connectionPool, table, idp, converter);
    }


    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public void save(V value) {
        value.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.save(value);
    }

    @Override
    public long updateHook(String action, AbstractEnvironment environment, List<Identifier> identifiers) {
        if (identifiers.isEmpty()) {
            return 0L;
        }
        long counter = 0L;
        ServiceEnvironment serviceEnvirnoment = (ServiceEnvironment) environment;
        SQLPermissionStore permissionStore = (SQLPermissionStore) serviceEnvirnoment.getPermissionStore();
        SQLClientApprovalStore approvalStore = (SQLClientApprovalStore) serviceEnvirnoment.getClientApprovalStore();
        PermissionKeys permissionKeys = (PermissionKeys) permissionStore.getMapConverter().getKeys();
        ConnectionRecord pCR; // for permissions
        ConnectionRecord aCR; // for approvals
        switch (action) {
            case UpkeepConstants.ACTION_NONE:
                return 0L;
            case UpkeepConstants.ACTION_TEST:
            case UpkeepConstants.ACTION_RETAIN:
                return identifiers.size();
            case UpkeepConstants.ACTION_ARCHIVE:
                StoreArchiver pStoreArchiver = new StoreArchiver(permissionStore);
                StoreArchiver aStoreArchiver = new StoreArchiver(approvalStore);
                pCR = permissionStore.getConnection();
                aCR = approvalStore.getConnection();

                try {
                    PreparedStatement pArchiveStmt = pCR.connection.prepareStatement(pStoreArchiver.createVersionStatement());
                    PreparedStatement aArchiveStmt = aCR.connection.prepareStatement(aStoreArchiver.createVersionStatement());
                    for (Identifier identifier : identifiers) {
                        pStoreArchiver.addToBatch(pArchiveStmt, identifier);
                        aStoreArchiver.addToBatch(aArchiveStmt, identifier);
                    }
                    counter = counter + pArchiveStmt.executeUpdate();
                    counter = counter + aArchiveStmt.executeUpdate();

                  permissionStore.releaseConnection(pCR);
                  approvalStore.releaseConnection(aCR);
                } catch (SQLException sqlException) {
                    if (DebugUtil.isEnabled()) {
                        sqlException.printStackTrace();
                    }
                    permissionStore.getConnectionPool().destroy(pCR);
                    approvalStore.getConnectionPool().destroy(aCR);
                }
                // NOTE that it is implicit in the contract for archive that the main records are deleted.
            case UpkeepConstants.ACTION_DELETE:
                String permissionStmt = "delete from " + permissionStore.getTable().getFQTablename() + " where " + permissionKeys.clientID() + "=?";
                String approvalStmt = "delete from " + approvalStore.getTable().getFQTablename() + " where " + permissionKeys.clientID() + "=?";
                 pCR = permissionStore.getConnection();
                 aCR = approvalStore.getConnection();
                try {

                    PreparedStatement pStmt = pCR.connection.prepareStatement(permissionStmt);
                    PreparedStatement aStmt = pCR.connection.prepareStatement(approvalStmt);
                    for (Identifier identifier : identifiers) {
                        pStmt.setString(1, identifier.toString());
                        pStmt.addBatch();
                        aStmt.setString(1, identifier.toString());
                        aStmt.addBatch();

                    }
                    long rc = pStmt.executeUpdate();
                    rc = rc + aStmt.executeUpdate();
                    if(action.equals(UpkeepConstants.ACTION_DELETE)) { // could have fallen through from archive. Don't count twice.
                        counter = counter + rc;
                    }
                    permissionStore.releaseConnection(pCR);
                    approvalStore.releaseConnection(aCR);
                } catch (SQLException sqlException) {
                    if (DebugUtil.isEnabled()) {
                        sqlException.printStackTrace();
                    }
                    permissionStore.getConnectionPool().destroy(pCR);
                    approvalStore.getConnectionPool().destroy(aCR);
                }
        }
        return counter;
    }
}
