package org.oa4mp.server.loader.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;

import javax.inject.Provider;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Note that the identifier is simple the JTI of the token and may be either an access or refresh
 * token. The important bit is that there si also a pernt id which is the auth grant of the original
 * service transaction. This is how they tie together.
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:40 AM
 */
public class SQLTXRecordStore<V extends TXRecord> extends SQLStore<V> implements TXStore<V> {
    public SQLTXRecordStore(ConnectionPool connectionPool,
                            TXRecordTable table,
                            Provider<V> identifiableProvider,
                            TXRecordConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    protected TXRecordTable getTXRTable() {
        return (TXRecordTable) getTable();
    }

    @Override
    public List<V> getByParentID(Identifier parentID) {
        List<V> values = new ArrayList<>();
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        V t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(getTXRTable().getSearchByParentIDStatement());
            stmt.setString(1, parentID.toString());
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the values.
            while (rs.next()) {
                ColumnMap map = rsToMap(rs);
                t = create();
                populate(map, t);
                values.add(t);
            }

            rs.close();
            stmt.close();
            releaseConnection(cr);
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error getting TX records that have parent \"" + parentID + "\"", e);
        }
        return values;
    }

    @Override
    public int getCountByParent(Identifier parentID) {
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        int rowCount = 0;
        try {
            PreparedStatement stmt = c.prepareStatement(getTXRTable().getCountByParentIDStatement());
            stmt.setString(1, parentID.toString());

            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            if (rs.next()) {
                rowCount = rs.getInt(1); // *trick* to get the row count
            }
            rs.close();
            stmt.close();
            releaseConnection(cr);
        } catch (SQLException e) {
            if(DebugUtil.isEnabled()){
                DebugUtil.trace(this, "caught SQL exception", e);
             }
            destroyConnection(cr);
            throw new GeneralException("Error getting the number of tx records for a parent id", e);
        }catch(Throwable t){
            if(DebugUtil.isEnabled()){
                DebugUtil.trace(this, "caught exception", t);
            }
            throw t;
        }
        return rowCount;
    }

    @Override
    public String getCreationTSField() {
        return ((TXRecordSerializationKeys)getMapConverter().getKeys()).issuedAt();
    }
}
