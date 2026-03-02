package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;

import javax.inject.Provider;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

public class KESQLStore<V extends KERecord> extends SQLStore<V> implements KEStore<V> {
    public KESQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    public KESQLStore() {
    }

    @Override
    public KEConverter<V> getXMLConverter() {
        return (KEConverter<V>) super.getXMLConverter();
    }

    @Override
    public String getCreationTSField() {
        return getXMLConverter().getKeys().creationTS();
    }

    KESerializationKeys getKeys() {
        return getXMLConverter().getKeys();
    }


    @Override
    public KERecord getByKID(String kid) {
        List<KERecord> keRecords = new ArrayList<>();
        String rawStmt = "select * from " + getTable().getFQTablename() + " where " + getKeys().kid() + "=?";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        V t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(rawStmt);
            stmt.setString(1, kid);
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the values.
            if (!rs.next()) {
                rs.close();
                stmt.close();
                releaseConnection(cr);
                return null;   // returning a null fulfills contract for this being a map.
            }

            ColumnMap map = rsToMap(rs);
            rs.close();
            stmt.close();
            releaseConnection(cr); // CIL-1833
            t = create();
            populate(map, t);
          //  setJWKDatesFromKERecord(t);
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error getting object with identifier \"" + kid + "\"", e);
        }
        return t;
    }

    /**
     * Used for setting the date in JWKs. If the date exists and is valid, then
     * return true Valid means that the long value is positive.
     *
     * @param date
     * @return
     */
    protected boolean isValidDate(Date date) {
        return date != null && 0 <= date.getTime();
    }

    @Override
    public HashSet<String> getKIDs() {
            HashSet<String> keys = new HashSet<>();
            String query = "Select " + getKeys().kid() + " from " + getTable().getFQTablename();
            ConnectionRecord cr = getConnection();
            Connection c = cr.connection;

            try {
                PreparedStatement stmt = c.prepareStatement(query);
                stmt.execute();
                ResultSet rs = stmt.getResultSet();
                // Figure out the type of argument. Can't do this in java without annoying reflection
                while (rs.next()) {
                    keys.add(rs.getString(1));
                }
                rs.close();
                stmt.close();
                releaseConnection(cr);

            } catch (SQLException e) {
                destroyConnection(cr);
                throw new GeneralException("Error getting the user ids", e);
            }
            return keys;
    }

    @Override
    public JSONWebKeys getCurrentKeys(VirtualIssuer vi) {
        Identifier viID = OA2SE.SERVER_VI_ID; // default.
        if(vi != null) viID = vi.getIdentifier();
        JSONWebKeys jsonWebKeys = new JSONWebKeys(null);
        String rawStatement = "SELECT * from " + getTable().getFQTablename() + " where " +
                getKeys().vi() + "=? AND " +
                getKeys().isValid() + "=1 AND " +
                "(" + getKeys().exp() + " is NULL OR ?<" + getKeys().exp() + ")"; // not expired yet.
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        V t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(rawStatement);
            stmt.setString(1, viID.toString());
            stmt.setLong(2, System.currentTimeMillis());
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the values.
            while (rs.next()) {
                ColumnMap map = rsToMap(rs);
                t = create();
                populate(map, t);
                jsonWebKeys.put(t.toJWK());
                if(t.getDefault()) jsonWebKeys.setDefaultKeyID(t.getKid());
            }

            rs.close();
            stmt.close();
            releaseConnection(cr);
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error getting all entries.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return jsonWebKeys;
    }
}
