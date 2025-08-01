package org.oa4mp.server.admin.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.io.File;
import java.sql.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/24 at  7:44 AM
 */
public class MigrateStore extends SQLStore<MigrationEntry> {

    public MigrateStore(ConnectionPool connectionPool, Table table, Provider identifiableProvider, MapConverter converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    protected MigrateKeys getKeys() {
        return (MigrateKeys) getMapConverter().getKeys();
    }

    @Override
    public String getCreationTSField() {
        return getKeys().create_ts();
    }

    /**
     * Gets the first batchSize undone elements for this migration.
     *
     * @param batchSize
     * @return
     */
    protected String getFetchStatement(int batchSize) {
        String s = "select * from " + getTable().getFQTablename() + " where " +
                getKeys().is_imported() + "=? AND " +
                getKeys().import_code() + "=? AND " +
                getKeys().store_type() + " =?";
        return s;
    }

    /**
     * Counts the number of entries for the given component in the database.
     *
     * @return
     */
    protected String countFetchStatement() {
        String s = "select count(*) from " + getTable().getFQTablename() + " where " +
                getKeys().is_imported() + " =? AND " +
                getKeys().import_code() + "=? AND " +
                getKeys().store_type() + " =?";
        return s;
    }

    /**
     * The statement that is used to ingest the source store.
     *
     * @return
     */
    protected String getIngestStatement() {
        String s = "insert into " + getTable().getFQTablename() +
                " (" +
                getKeys().path() + "," +
                getKeys().filename() + "," +
                getKeys().store_type() + "," +
                getKeys().import_code() + "," +
                getKeys().error_message() + "," +
                getKeys().is_imported() +
                ") values (?,?,?,?,?,false)";
        return s;
    }

    /**
     * Migration store entry after import. This reports the result of trying to import the
     * item to the store.
     *
     * @return
     */
    protected String getUpdateStatement() {
        String s = "update  " + getTable().getFQTablename() +
                "  set " +
                getKeys().is_imported() + "=?," +
                getKeys().import_code() + "=?," +
                getKeys().error_message() + "=?," +
                getKeys().import_ts() + "=?" +
                " where " + getKeys().filename() + "=? AND " + getKeys().store_type() + "=?";
        return s;
    }


    @Override
    public DerbyConnectionPool getConnectionPool() {
        return (DerbyConnectionPool) super.getConnectionPool();
    }


    /**
     * Does this store exist?
     *
     * @return
     */
    public boolean exists() {
        File f = new File(getConnectionPool().getConnectionParameters().getDatabaseName());
        return f.exists();
    }

    public int resetImportCodes(String component) throws SQLException {
        String resetCodeStatement = "update " + getTable().getFQTablename() + " set " + getKeys().import_code() + "=?";
        resetCodeStatement = resetCodeStatement + ", " + getKeys().error_message() + "=?";
        boolean hasComponent = !StringUtils.isTrivial(component);
        if(hasComponent){
            resetCodeStatement  = resetCodeStatement + " where " + getKeys().store_type() + "=?";
        }
        ConnectionRecord connectionRecord = getConnectionPool().pop();
        Connection connection = getConnection().connection;
        int out = 0;
        try {
            PreparedStatement p  = connection.prepareStatement(resetCodeStatement);
            p.setInt(1, 0);
            p.setNull(2, Types.LONGVARCHAR);
            if(hasComponent) {
                p.setString(3, component.toLowerCase());
            }
            out = p.executeUpdate();
            p.close();
            connection.close();
            releaseConnection(connectionRecord);
            return out;
        } catch (SQLException sqlException) {
           destroyConnection(connectionRecord);
           throw sqlException;
        }
    }

}
