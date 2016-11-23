package edu.uiuc.ncsa.co.ldap;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
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

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  4:00 PM
 */
public class LDAPSQLStore<V extends LDAPEntry> extends SQLStore<V> implements LDAPStore<V>{
    public static String DEFAULT_TABLENAME="ldap";
    public LDAPSQLStore() {
    }

    public LDAPSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public LDAPEntry getByClientID(Identifier clientID) {
        Connection c = getConnection();
        LDAPEntryKeys keys = new LDAPEntryKeys();
        V newOne = null;

        try {
            PreparedStatement stmt = c.prepareStatement("select * from " +
                    getTable().getFQTablename() + " where " + keys.clientID() + "=?");
            stmt.setString(1, clientID.toString());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                newOne = create();
                ColumnMap map = rsToMap(rs);
                populate(map, newOne);
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error: could not get database object", e);
        } finally {
            releaseConnection(c);
        }
        return newOne;
    }
}
