package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/13/16 at  3:58 PM
 */
public class SQLPermissionStore<V extends Permission> extends SQLStore<V> implements PermissionsStore<V> {
    @Override
    public String getCreationTSField() {
        return null;
    }

    public static String DEFAULT_TABLENAME = "permissions";

    public SQLPermissionStore() {
    }

    public SQLPermissionStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public PermissionList get(Identifier adminID, Identifier clientID) {
        PermissionList allOfThem = new PermissionList();
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

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
            destroyConnection(cr);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(cr);
        }
        return allOfThem;
    }

    @Override
    public PermissionList getErsatzChains(Identifier adminID, Identifier clientID) {
        PermissionList allOfThem = new PermissionList();
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        PermissionKeys permissionKeys = new PermissionKeys();
        try {
            PreparedStatement stmt = c.prepareStatement("select * from " +
                    getTable().getFQTablename() + " where " + permissionKeys.clientID() + "=? AND " +
                    permissionKeys.adminID() + "=? AND " + permissionKeys.substitute() + "=1");
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
            destroyConnection(cr);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(cr);
        }
        return allOfThem;
    }

    @Override
    public Permission getErsatzChain(Identifier adminID, Identifier clientID, Identifier ersatzID) {
        return PermissionStoreUtil.getErsatzChain(this, adminID, clientID, ersatzID);
    }

    @Override
    public int getClientCount(Identifier adminID) {
        ArrayList<Identifier> clients = new ArrayList<>();
        if (adminID == null) return 0;

        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        PermissionKeys permissionKeys = new PermissionKeys();
        try {
            PreparedStatement stmt = c.prepareStatement("select COUNT(*)  from " +
                    getTable().getFQTablename() + " where " + permissionKeys.adminID() + "=?");
            stmt.setString(1, adminID.toString());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            rs.next();
            int totalClients = rs.getInt(1);
            rs.close();
            stmt.close();
            return totalClients;
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(cr);
        }
    }

    @Override
    public List<Identifier> getClients(Identifier adminID) {
        ArrayList<Identifier> clients = new ArrayList<>();
        if (adminID == null) return clients;

        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        PermissionKeys permissionKeys = new PermissionKeys();
        try {
            PreparedStatement stmt = c.prepareStatement("select " + permissionKeys.clientID() + "  from " +
                    getTable().getFQTablename() + " where " + permissionKeys.adminID() + "=?");
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
            destroyConnection(cr);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(cr);
        }
        return clients;
    }

    @Override
    public List<Identifier> getAdmins(Identifier clientID) {
        ArrayList<Identifier> admins = new ArrayList<>();
        // With the advent of ersatz clients, there may be multiple entries for a given client
        HashSet<Identifier> uniqueIDs = new HashSet<>();
        if (clientID == null) return admins;

        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        PermissionKeys permissionKeys = new PermissionKeys();
        try {
            PreparedStatement stmt = c.prepareStatement("select " + permissionKeys.adminID() + "  from " +
                    getTable().getFQTablename() + " where " + permissionKeys.clientID() + "=?");
            stmt.setString(1, clientID.toString());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                String adminID = rs.getString(permissionKeys.adminID());
                uniqueIDs.add(BasicIdentifier.newID(adminID));
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(cr);
        }
        admins.addAll(uniqueIDs);
        return admins;
    }

    @Override
    public boolean hasEntry(Identifier adminID, Identifier clientID) {
        return !get(adminID, clientID).isEmpty();
    }

}
