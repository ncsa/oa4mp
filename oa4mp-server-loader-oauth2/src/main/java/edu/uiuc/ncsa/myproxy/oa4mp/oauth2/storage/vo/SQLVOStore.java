package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
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

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/19/21 at  4:48 PM
 */
public class SQLVOStore<V extends VirtualOrganization> extends SQLStore<V> implements VOStore<V> {
    public SQLVOStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public V findByPath(String component) {
        String pathQuery = "select * from " + getTable().getFQTablename()
                + " where "
                + ((VOSerializationKeys) getMapConverter().getKeys()).discoveryPath()
                + " = ?";
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        V vo = null;
        try {
            PreparedStatement stmt = c.prepareStatement(pathQuery);
            stmt.setString(1, component);
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
            vo = create();
            populate(map, vo);
            releaseConnection(cr);
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error getting virtual organization with path component \"" + component + "\"", e);
        }
        return vo;
    }

    @Override
    public void save(V value) {
        value.setLastModified(System.currentTimeMillis());
        super.save(value);
    }

    @Override
    public void update(V value) {
        value.setLastModified(System.currentTimeMillis());
        super.update(value);
    }
}

