package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql;

import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.table.ClientApprovalTable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 26, 2011 at  9:39:26 AM
 */
public class SQLClientApprovalStore extends SQLStore<ClientApproval> implements ClientApprovalStore<ClientApproval> {
     public static final String DEFAULT_TABLENAME = "client_approvals";

    public SQLClientApprovalStore(ConnectionPool connectionPool,
                                  Table table,
                                  IdentifiableProviderImpl<ClientApproval> identifiableProvider,
                                  MapConverter converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    ClientApprovalTable getCAT(){
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
                      + " where " + getCAT().ca().approved() + "=true ";
              Connection c = getConnection();
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
                  destroyConnection(c);
                  throw new GeneralException("Error getting the user ids", e);
              } finally {
                  releaseConnection(c);
              }
        return count;
    }
}
