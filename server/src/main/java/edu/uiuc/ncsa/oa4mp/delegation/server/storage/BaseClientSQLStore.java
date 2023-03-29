package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClientKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.monitored.MonitoredSQLStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

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
//public abstract class BaseClientSQLStore<V extends BaseClient> extends SQLStore<V> implements BaseClientStore<V>  {
public abstract class BaseClientSQLStore<V extends BaseClient> extends MonitoredSQLStore<V> implements BaseClientStore<V>  {

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
        BaseClientKeys keys = (BaseClientKeys)getMapConverter().getKeys();
        return keys.creationTS();
    }
}
