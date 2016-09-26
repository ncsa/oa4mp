package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
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
 * on 1/28/13 at  2:11 PM
 */
public class SQLAssetStore extends SQLStore<Asset> implements AssetStore {
    public static final String DEFAULT_TABLENAME = "transactions";

    public SQLAssetStore() {
    }

    public SQLAssetStore(ConnectionPool connectionPool, Table table, Provider<Asset> assetProvider, MapConverter<Asset> converter) {
        super(connectionPool, table, assetProvider, converter);
    }

    @Override
    public Asset get(String identifier) {
        return AssetStoreUtil.get(identifier, this);
    }

    @Override
    public void save(String identifier, Asset asset) {
        AssetStoreUtil.save(identifier, asset, this);
    }

    protected AssetStoreTable getAST() {
        return (AssetStoreTable) getTable();
    }


    @Override
    public Asset getByToken(Identifier token) {
        if (token == null) {
            return null;
        }
        Connection c = getConnection();
        Asset t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(getAST().getByTokenStatement());
            stmt.setString(1, token.toString());
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            // Now we have to pull in all the values.
            if (!rs.next()) {
                rs.close();
                stmt.close();
                return null;   // returning a null fulfills contract for this being a map.
            }

            ColumnMap map = rsToMap(rs);
            rs.close();
            stmt.close();

            t = create();
            populate(map, t);
        } catch (SQLException e) {
            destroyConnection(c);
            throw new GeneralException("Error getting object with identifier \"" + token + "\"", e);
        } finally {
            releaseConnection(c);
        }
        return t;
    }

    @Override
    public void putByToken(Asset asset) {
           save(asset);
    }
}
