package org.oa4mp.delegation.server.storage;

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
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.BaseClientKeys;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;

import javax.inject.Provider;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/6/21 at  2:44 PM
 */
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
        BaseClientKeys baseClientKeys = (BaseClientKeys) getMapConverter().getKeys();
        String clientID = baseClientKeys.identifier();
        String approvalID = caKeys.identifier();
        String clientTableName = getTable().getFQTablename();
        String approvalTableName = caStore.getTable().getFQTablename();
        // https://github.com/ncsa/oa4mp/issues/244 sort the result by client creatio time stamp. Newest first.
        String query = "select p." + clientID + ", p." + baseClientKeys.creationTS() + " from " + clientTableName +
                " as p left join " + approvalTableName + " as s on p." + clientID +
                " = s." + approvalID + " where s." + fieldName + " = ? ORDER BY p." + baseClientKeys.creationTS() + " DESC";

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
               /*
WRONG:
select client_id, creation_ts, last_modified_ts, last_accessed from oauth2.clients
   where creation_ts<='2023-02-14 07:39:38.997' AND  '2023-08-18 14:39:38.997'<=creation_ts;

RIGHT:
select client_id, creation_ts, last_modified_ts, last_accessed from oauth2.clients where
    '2023-02-14 07:39:38.997'<=creation_ts AND creation_ts<= '2023-08-18 14:39:38.997';
            */

/*
    String filterToSQL(RuleFilter filter, String ruleType, String key) {
        String query = "";
        long now = System.currentTimeMillis();
        HashMap<String, DateThingy> createdDates = filter.getByType(ruleType);
        boolean applies = false;
        if (createdDates.containsKey(RuleFilter.WHEN_AFTER)) {
            DateThingy dateThingy = createdDates.get(RuleFilter.WHEN_AFTER);
            if (dateThingy.isRelative()) {
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
*/

    protected BaseClientKeys getKeys() {
        return (BaseClientKeys) getMapConverter().getKeys();
    }

}
