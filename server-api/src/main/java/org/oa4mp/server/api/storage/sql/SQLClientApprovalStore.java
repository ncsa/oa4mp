package org.oa4mp.server.api.storage.sql;

import org.oa4mp.server.api.storage.sql.table.ClientApprovalTable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugConstants;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 26, 2011 at  9:39:26 AM
 */
public class SQLClientApprovalStore extends SQLStore<ClientApproval> implements ClientApprovalStore<ClientApproval> {
    @Override
    public String getCreationTSField() {
        return ((ClientApprovalKeys)getMapConverter().getKeys()).approvalTS();
    }

    public static final String DEFAULT_TABLENAME = "client_approvals";

    public SQLClientApprovalStore(ConnectionPool connectionPool,
                                  Table table,
                                  IdentifiableProviderImpl<ClientApproval> identifiableProvider,
                                  MapConverter converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    ClientApprovalTable getCAT() {
        return (ClientApprovalTable) getTable();
    }

    @Override
    public boolean isApproved(Identifier identifier) {
        ClientApproval c = get(identifier);
        if (c == null) return false;
        return c.isApproved();
    }

    @Override
    public int getUnapprovedCount() {
        int count = 0;

        String query = "Select " + getTable().getPrimaryKeyColumnName() + " from " + getTable().getFQTablename()
                + " where " + getCAT().ca().approved() + "=false ";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.execute();
            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                count++;
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(cr);
            if(DebugUtil.getDebugLevel() == DebugConstants.DEBUG_LEVEL_TRACE){
                e.printStackTrace();
            }
            DebugUtil.trace("sql error", e);
            throw new GeneralException("Error getting the user ids", e);
        } finally {
            releaseConnection(cr);
        }
        return count;
    }

    @Override
    public int getPendingCount() {
        int count = 0;

        String query = "Select " + getTable().getPrimaryKeyColumnName() + " from " + getTable().getFQTablename()
                + " where " + getCAT().ca().approved() + "=false ";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        try {
            PreparedStatement stmt = c.prepareStatement(query);
            stmt.execute();
            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                count++;
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(cr);
            if(DebugUtil.getDebugLevel() == DebugConstants.DEBUG_LEVEL_TRACE){
                e.printStackTrace();
            }
            DebugUtil.trace("sql error", e);
            throw new GeneralException("Error getting the user ids", e);
        } finally {
            releaseConnection(cr);
        }
        return count;
    }

    @Override
    public List<Identifier> statusSearch(String status) {

        List<Identifier> ids = new ArrayList<>();
        ClientApprovalKeys keys = (ClientApprovalKeys) getMapConverter().getKeys();
        String idColName = keys.identifier();
        String searchString = "select " + idColName + " from " + getTable().getFQTablename() +
                " where " + keys.status() + " = ?";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        try {
            PreparedStatement stmt = c.prepareStatement(searchString);
            stmt.setString(1, status);
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the identifiers.
            while (rs.next()) {
                ids.add(new BasicIdentifier(rs.getString(idColName)));
            }

            rs.close();
            stmt.close();
            releaseConnection(cr);
        } catch (SQLException e) {
            destroyConnection(cr);
            if(DebugUtil.isEnabled()){
                e.printStackTrace();
            }
            throw new GeneralException("Error getting client approval", e);
        }

        return ids;
    }
}
