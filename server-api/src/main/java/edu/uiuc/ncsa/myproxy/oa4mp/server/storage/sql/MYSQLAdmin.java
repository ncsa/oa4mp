package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql;

import edu.uiuc.ncsa.security.storage.sql.DBInitializer;

import java.sql.SQLException;
import java.sql.Statement;

/**
 * Planned administrative utility. Right now there are supplied scripts for this.
 * <p>Created by Jeff Gaynor<br>
 * on May 17, 2011 at  1:47:12 PM
 */
public class MYSQLAdmin extends DBInitializer {
    @Override
    public void createSchema(Statement s) throws SQLException {
        String stmt = "CREATE DATABASE oauth";
    }

    @Override
    public void setPermissions(Statement s) throws SQLException {
    }

    @Override
    public void dropSchema(Statement s) throws SQLException {
        // This does automatic cascade, unlike Postgres.
        // DROP DATABASE TGO;
    }

    @Override
    public void createTables(Statement s) throws SQLException {
    }

    @Override
    public void recreateTransactionTables(Statement s) throws SQLException {

    }

    @Override
    public void dropTables(Statement s) throws SQLException {
    }
}
