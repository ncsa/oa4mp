package org.oa4mp.delegation.server.storage;

import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.BaseClientKeys;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import org.oa4mp.delegation.server.storage.uuc.DateThingy;
import org.oa4mp.delegation.server.storage.uuc.RuleFilter;
import org.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredSQLStore;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
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

    /*
    Typical relative looks like
       (created <= (now - after)) AND ((now - before) <= created)
     Typical ISO 8601 looks like
       (after <= created ) AND (created <= before)

      N.B. if R is relative offset and I is the actual ISO date, then
           for time NOW
             NOW - R = I  => NOW = I + R
     */
    String filterToSQL(RuleFilter filter, String ruleType, String key) {
        String query = "";
        long now = System.currentTimeMillis();
        HashMap<String, DateThingy> createdDates = filter.getByType(ruleType);
        boolean applies = false;
        if (createdDates.containsKey(RuleFilter.WHEN_AFTER)) {
            DateThingy dateThingy = createdDates.get(RuleFilter.WHEN_AFTER);
            if (dateThingy.isRelative()) {
           /*
WRONG:
select client_id, creation_ts, last_modified_ts, last_accessed from oauth2.clients
   where creation_ts<='2023-02-14 07:39:38.997' AND  '2023-08-18 14:39:38.997'<=creation_ts;

RIGHT:
select client_id, creation_ts, last_modified_ts, last_accessed from oauth2.clients where
    '2023-02-14 07:39:38.997'<=creation_ts AND creation_ts<= '2023-08-18 14:39:38.997';
            */
                //query = query + key + "<=" + (now - dateThingy.getRelativeDate());
                query = query + " '" + new Timestamp(now - dateThingy.getRelativeDate()) + "'<=" + key;
                //applies = created + dateThingy.relativeDate <= System.currentTimeMillis();
            } else {
                //query = query + key + "<=" + (dateThingy.getIso8601().getTime());
                query = query + " '" + new Timestamp(dateThingy.getIso8601().getTime()) + "'<=" + key;
                //applies = created <= dateThingy.iso8601.getTime();
            }
        }
        if (createdDates.containsKey(RuleFilter.WHEN_BEFORE)) {
            DateThingy dateThingy = createdDates.get(RuleFilter.WHEN_BEFORE);
            query = query + (query.length() == 0 ? " " : " AND "); // add connector if needed
            if (dateThingy.isRelative()) {
                //query = query + (now - dateThingy.getRelativeDate()) + "<=" + key;
                query = query + key + "<='" + new Timestamp(now - dateThingy.getRelativeDate()) + "'";
                //applies = applies && (  System.currentTimeMillis() <= created + dateThingy.relativeDate);
            } else {
                //query = query + dateThingy.getIso8601().getTime() + "<=" + key;
                query = query + key + "<='" + new Timestamp(dateThingy.getIso8601().getTime()) + "'";
                // applies = applies && (  dateThingy.iso8601.getTime() <= created);
            }
        }
        System.out.println(getClass().getSimpleName() + "filter query=" + query);
        return query;
    }

    protected String createFilter(RuleFilter filter) {
        String query = "";
        if (filter == null) return query;

        return query;
    }

    protected BaseClientKeys getKeys() {
        return (BaseClientKeys) getMapConverter().getKeys();
    }


    protected String createUUCQueryNEW(UUCConfiguration uucConfiguration) {
        BaseClientKeys keys = getKeys();
        String query = "select " + keys.identifier() + ", " + keys.creationTS() + ", " + keys.lastModifiedTS() + ", " + keys.lastAccessed()
                + " from " + getTable().getFQTablename();
        if (uucConfiguration.hasFilter() && !uucConfiguration.hasSubFilter()) {
            // if there is one filter at the top level, then use that for everything.
            // otherwise, filtering has to be done on everything.
            query = query + " where " + filterToSQL(uucConfiguration.getFilter(), RuleFilter.TYPE_CREATED, keys.creationTS());
        }
        return query;
    }

    protected String createUUCQueryOLD(UUCConfiguration uucConfiguration) {
        BaseClientKeys keys = getKeys();
        String query = "select " + keys.identifier() + ", " + keys.creationTS() + ", " + keys.lastModifiedTS() + ", " + keys.lastAccessed()
                + " from " + getTable().getFQTablename() + " where ";
        if (uucConfiguration.unusedClientsOnly()) {
            query = query + keys.lastAccessed() + "=0 OR " + keys.lastAccessed() + " is NULL";
        } else {
            if (uucConfiguration.hasLastAccessedAfter()) {
                // delete between dates
                query = query +
                        uucConfiguration.lastAccessedAfter + "<=" + keys.lastAccessed() + " AND " + keys.lastAccessed() + "<=" + uucConfiguration.lastAccessedBefore;
            } else {
                // delete everything before the given last accessed date
                query = query + keys.lastAccessed() + "<=" + uucConfiguration.lastAccessedBefore;
            }
        }
        return query;
    }

/*  public UUCResponse unusedClientCleanup(UUCConfiguration uucConfiguration) {
        String query = createUUCQueryNEW(uucConfiguration);
        //String query = createUUCQueryOLD(uucConfiguration);
        BaseClientKeys keys = getKeys();
        System.out.println(getClass().getSimpleName() + ": query=" + query);
        String deleteStmt = "delete from " + getTable().getFQTablename() + " where " + keys.identifier() + "=?";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        StoreArchiver storeArchiver = new StoreArchiver(this);
        int totalFound = 0;
        int numberProcessed = 0;
        int skipped = 0;
        List<String> toRemove = new ArrayList<>();
        List<String> toArchive = new ArrayList<>();
        UUCRetentionPolicy uucRetentionPolicy = new UUCRetentionPolicy(this, uucConfiguration);
        try { // create statements needed
            Statement stmt = c.createStatement();
            PreparedStatement deletepStmt = c.prepareStatement(deleteStmt);
            String aQuery = storeArchiver.createVersionStatement();
            System.out.println(getClass().getSimpleName() + " a query=\"" + aQuery + "\"");
            PreparedStatement archiveStmt = c.prepareStatement(aQuery);

            stmt.executeQuery(query);
            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                totalFound++;
                Timestamp createTS = rs.getTimestamp(keys.creationTS());
                Timestamp lastModifiedTS = rs.getTimestamp(keys.lastModifiedTS()); //may be null
                long aa = rs.getLong(keys.lastAccessed());
                Timestamp lastAccessed = null;
                if (!rs.wasNull()) { // check if it was really null, since getLong sets the value to 0 if it is null or 0.
                    lastAccessed = new Timestamp(aa); // may be null
                }
                Identifier identifier = BasicIdentifier.newID(rs.getString(keys.identifier()));
                int[] rc = uucRetentionPolicy.retain(identifier, createTS, lastAccessed, lastModifiedTS);
                if (rc[0] == 1) {
                    skipped++;
                } else {
                    numberProcessed++;
                    if (!uucConfiguration.testMode) {
                        // Global override in configuration to do testing.
                        MetaRule metaRule = uucConfiguration.getRule(rc[1]);
                        RuleFilter filter = null;
                        if(metaRule.hasFilter()){
                            filter = metaRule.getFilter().overrideFromParent(uucConfiguration.getFilter());
                        }
                        switch (metaRule.getAction()) {
                            case UUCConfiguration.ACTION_DELETE:
                                toRemove.add(identifier.toString());
                                deletepStmt.setString(1, identifier.toString());
                                deletepStmt.addBatch();
                                break;
                            case UUCConfiguration.ACTION_TEST:
                                break;
                            case UUCConfiguration.ACTION_ARCHIVE:
                                storeArchiver.addToBatch(archiveStmt, identifier);
                                toArchive.add(identifier.toString());
                                break;
                        }
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
            int[] deletedRecords = deletepStmt.executeBatch();
            ResultStats deletedStats = gatherStats(deletedRecords);
            int[] archivedRecords = archiveStmt.executeBatch();
            ResultStats archivedStats = gatherStats(archivedRecords);
            deletepStmt.close();
            archiveStmt.close();
            releaseConnection(cr);
            UUCResponse uucResponse = new UUCResponse();
            uucResponse.archivedStats = archivedStats;
            uucResponse.deletedStats = deletedStats;
            uucResponse.attempted = numberProcessed;
            uucResponse.total = totalFound;
            uucResponse.skipped = skipped;
            uucResponse.found = toRemove;
            uucResponse.archived = toArchive;
            return uucResponse;
        } catch (SQLException e) {
            destroyConnection(cr);
            if (DebugUtil.isEnabled()) {
                e.printStackTrace();
            }
            throw new GeneralException("Error getting last accessed information for clients", e);
        }
    }

    protected ResultStats gatherStats(int[] records) {
        int success = 0;
        int noInfo = 0;
        int failed = 0;
        int unknown = 0;
        for (int i = 0; i < records.length; i++) {
            int current = records[i];
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
        ResultStats resultStats
                = new ResultStats(success, noInfo, failed, unknown);
        return resultStats;
    }
*/
}
