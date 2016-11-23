package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
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
 * on 10/13/16 at  3:58 PM
 */
public class SQLPermissionStore<V extends Permission> extends SQLStore<V> implements PermissionsStore<V> {
    public static String DEFAULT_TABLENAME = "permissions";

    public SQLPermissionStore() {
    }

    public SQLPermissionStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public PermissionList get(Identifier adminID, Identifier clientID) {
        PermissionList allOfThem = new PermissionList();
        Connection c = getConnection();
        PermissionKeys permissionKeys = new PermissionKeys();
        try {
            PreparedStatement stmt = c.prepareStatement("select * from " +
                    getTable().getFQTablename() + " where " + permissionKeys.clientID() + "=? AND " +
            permissionKeys.adminID() + "=?");
            stmt.setString(1, clientID.toString());
            stmt.setString(2, adminID.toString());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                V newOne = create();
                ColumnMap map = rsToMap(rs);
                populate(map, newOne);
                allOfThem.add(newOne);
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(c);
        }
        return allOfThem;
    }

    @Override
    public List<Identifier> getClients(Identifier adminID) {
        ArrayList<Identifier> clients = new ArrayList<>();
        if(adminID == null) return clients;

          Connection c = getConnection();
          PermissionKeys permissionKeys = new PermissionKeys();
          try {
              PreparedStatement stmt = c.prepareStatement("select " + permissionKeys.clientID() + "  from " +
                      getTable().getFQTablename() + " where " +permissionKeys.adminID() + "=?");
              stmt.setString(1, adminID.toString());
              stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

              ResultSet rs = stmt.getResultSet();
              while (rs.next()) {
                  String clientID = rs.getString(permissionKeys.clientID());
                  clients.add(BasicIdentifier.newID(clientID));
              }
              rs.close();
              stmt.close();
          } catch (SQLException e) {
              destroyConnection(c);
              throw new GeneralException("Error: could not get database object", e);
          } finally {
              releaseConnection(c);
          }
          return clients;
    }

    @Override
    public List<Identifier> getAdmins(Identifier clientID) {
            ArrayList<Identifier> admins = new ArrayList<>();
        if(clientID == null) return admins;

        Connection c = getConnection();
        PermissionKeys permissionKeys = new PermissionKeys();
               try {
                   PreparedStatement stmt = c.prepareStatement("select " + permissionKeys.adminID() + "  from " +
                           getTable().getFQTablename() + " where " +permissionKeys.clientID() + "=?");
                   stmt.setString(1, clientID.toString());
                   stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

                   ResultSet rs = stmt.getResultSet();
                   while (rs.next()) {
                       String adminID = rs.getString(permissionKeys.adminID());
                       admins.add(BasicIdentifier.newID(adminID));
                   }
                   rs.close();
                   stmt.close();
               } catch (SQLException e) {
                   destroyConnection(c);
                   throw new GeneralException("Error: could not get database object", e);
               } finally {
                   releaseConnection(c);
               }
               return admins;
    }

    @Override
    public boolean hasEntry(Identifier adminID, Identifier clientID) {
        return !get(adminID, clientID).isEmpty();
    }
}
