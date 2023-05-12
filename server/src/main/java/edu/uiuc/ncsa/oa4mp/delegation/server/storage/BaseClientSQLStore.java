package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClientKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored.MonitoredSQLStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCRetentionPolicy;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.cli.StoreArchiver;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/6/21 at  2:44 PM
 */
//public abstract class BaseClientSQLStore<V extends BaseClient> extends SQLStore<V> implements BaseClientStore<V>  {
public abstract class BaseClientSQLStore<V extends BaseClient> extends MonitoredSQLStore<V> implements BaseClientStore<V> {

    public BaseClientSQLStore(ConnectionPool connectionPool,
                              Table table,
                              Provider<V> idp,
                              MapConverter converter
    ) {
        super(connectionPool, table, idp, converter);
    }

    /**
     * Get by status from the approval store. This uses a left join and should return
     * the ids of elements with approvals that have the given status.
     *
     * @param status
     * @param clientApprovalStore
     * @return
     */
    @Override
    public List<Identifier> getByStatus(String status, ClientApprovalStore clientApprovalStore) {
        SQLStore caStore = (SQLStore) clientApprovalStore;
        ClientApprovalKeys caKeys = (ClientApprovalKeys) caStore.getMapConverter().getKeys();
        return getByField(caKeys.status(), status, clientApprovalStore);
    }

    @Override
    public List<Identifier> getByApprover(String approver, ClientApprovalStore clientApprovalStore) {
        SQLStore caStore = (SQLStore) clientApprovalStore;
        ClientApprovalKeys caKeys = (ClientApprovalKeys) caStore.getMapConverter().getKeys();
        return getByField(caKeys.approver(), approver, clientApprovalStore);
    }

    public List<Identifier> getByField(String fieldName, String field, ClientApprovalStore clientApprovalStore) {
        List<Identifier> ids = new ArrayList<>();
        if (!(clientApprovalStore instanceof SQLStore)) {
            throw new IllegalStateException("Cannot perform this against a non-SQL store. ");
        }
        SQLStore caStore = (SQLStore) clientApprovalStore;
        // so now we have to create a very specific left join to get this information, which is why
        // everything has to live in the same database.
        ClientApprovalKeys caKeys = (ClientApprovalKeys) caStore.getMapConverter().getKeys();
        String clientID = getMapConverter().getKeys().identifier();
        String approvalID = caKeys.identifier();
        String clientTableName = getTable().getFQTablename();
        String approvalTableName = caStore.getTable().getFQTablename();

        String query = "select p." + clientID + " from " + clientTableName +
                " as p left join " + approvalTableName + " as s on p." + clientID +
                " = s." + approvalID + " where s." + fieldName + " = ?";

        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        V t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.setString(1, field);
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the values.
            while (rs.next()) {
                ids.add(new BasicIdentifier(rs.getString(clientID)));
            }

            rs.close();
            stmt.close();
            releaseConnection(cr);
        } catch (SQLException e) {
            destroyConnection(cr);
            if (DebugUtil.isEnabled()) {
                e.printStackTrace();
            }
            throw new GeneralException("Error getting approvals for status \"" + field + "\"", e);
        }
        return ids;
    }

    @Override
    public String getCreationTSField() {
        BaseClientKeys keys = (BaseClientKeys) getMapConverter().getKeys();
        return keys.creationTS();
    }


    @Override
    public UUCResponse unusedClientCleanup(UUCConfiguration uucConfiguration) {
        BaseClientKeys keys = (BaseClientKeys) getMapConverter().getKeys();
        String query =  "select " + keys.identifier() + ", " + keys.creationTS() + ", " + keys.lastModifiedTS()
                           + " from " + getTable().getFQTablename() + " where " ;
        if(uucConfiguration.unusedClientsOnly()){
            query =query +  keys.lastAccessed() + "=0 OR " + keys.lastAccessed() + " is NULL";
        }else{
            if(uucConfiguration.hasLastAccessedAfter()){
                // delete between dates
                query = query +
                        uucConfiguration.lastAccessedAfter + "<="+ keys.lastAccessed() + " AND " + keys.lastAccessed() + "<="+uucConfiguration.lastAccessed;
            }else{
                // delete everything before the given last accessed date
                query = query + keys.lastAccessed() + "<="+uucConfiguration.lastAccessed;
            }

        }

        String deleteStmt = "delete from " + getTable().getFQTablename() + " where " + keys.identifier() + "=?";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        StoreArchiver storeArchiver = new StoreArchiver(this);
        long now = System.currentTimeMillis();
        int totalFound = 0;
        int numberProcessed = 0;
        int skipped = 0;
        List<String> toRemove = new ArrayList<>();
        UUCRetentionPolicy uucRetentionPolicy = new UUCRetentionPolicy(this, uucConfiguration);
        try {
            Statement stmt = c.createStatement();
            stmt.executeQuery(query);
            ResultSet rs = stmt.getResultSet();
            PreparedStatement deletepStmt = c.prepareStatement(deleteStmt);
            while (rs.next()) {
                totalFound++;
                Timestamp createTS = rs.getTimestamp(keys.creationTS());
                Timestamp lastModifiedTS = rs.getTimestamp(keys.lastModifiedTS());
                String id = rs.getString(keys.identifier());
                if (uucRetentionPolicy.retain(id, createTS, lastModifiedTS)) {
                    skipped++;
                }else{
                    numberProcessed++;
                    toRemove.add(id);
                    if (!uucConfiguration.testMode) {
                        deletepStmt.setString(1, rs.getString(keys.identifier()));
                        deletepStmt.addBatch();
                    }

                }
            }
            rs.close();
            stmt.close();
            if (!uucConfiguration.testMode) {
                releaseConnection(cr);

                UUCResponse uucResponse = new UUCResponse();
                uucResponse.attempted = numberProcessed;
                uucResponse.total = totalFound;
                uucResponse.found = toRemove;
                uucResponse.skipped = skipped;
                return uucResponse;
            }
            int[] affectedRecords = deletepStmt.executeBatch();
            int success = 0;
            int noInfo = 0;
            int failed = 0;
            int unknown = 0;
            for (int i = 0; i < affectedRecords.length; i++) {
                int current = affectedRecords[i];
                switch (current) {
                    case Statement.SUCCESS_NO_INFO:
                        noInfo++;
                        break;
                    case Statement.EXECUTE_FAILED:
                        failed++;
                        break;
                    default:
                        if (current < 0) {
                            unknown += current;
                        } else {
                            success += current;
                        }
                        break;
                }
            }
            deletepStmt.close();
            UUCResponse uucResponse = new UUCResponse();
            uucResponse.attempted = numberProcessed;
            uucResponse.no_info = noInfo;
            uucResponse.unknown = unknown;
            uucResponse.failed = failed;
            uucResponse.success = success;
            uucResponse.total = totalFound;
            uucResponse.skipped = skipped;
            uucResponse.found = toRemove;
            releaseConnection(cr);
            return uucResponse;
        } catch (SQLException e) {
            destroyConnection(cr);
            if (DebugUtil.isEnabled()) {
                e.printStackTrace();
            }
            throw new GeneralException("Error getting last accessed information for clients", e);
        }
    }
}
