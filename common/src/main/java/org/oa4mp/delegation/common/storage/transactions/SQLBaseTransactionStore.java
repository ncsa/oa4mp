package org.oa4mp.delegation.common.storage.transactions;

import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
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
 * Generic SQL implementation. This is SQL:2003 compliant and should work with most major
 * vendors databases without change.
 * <p>Created by Jeff Gaynor<br>
 * on May 10, 2010 at  3:45:05 PM
 */
abstract public class SQLBaseTransactionStore<V extends BasicTransaction> extends SQLStore<V> implements TransactionStore<V> {
    protected TokenForge tokenForge;

    protected SQLBaseTransactionStore(TokenForge tokenForge, ConnectionPool connectionPool, Table table,
                                      Provider<V> idp,
                                      MapConverter converter) {
        super(connectionPool, table, idp, converter);
        this.tokenForge = tokenForge;
    }


    public BasicTransactionTable getTransactionTable() {
        return (BasicTransactionTable) getTable();
    }

    /**
     * Since there are several possible statements (by temp cred, access token, verifier) that
     * will return a transaction, this method will handle them all.
     *
     * @param identifier
     * @param statement
     * @return
     */
    protected V getTransaction(String identifier, String statement) {

        if (identifier == null) {
            throw new IllegalStateException("a null identifier was supplied");
        }
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;

        V t = null;
        try {
            PreparedStatement stmt = c.prepareStatement(statement);
            stmt.setString(1, identifier);
            stmt.executeQuery();
            ResultSet rs = stmt.getResultSet();
            if (!rs.next()) {
                rs.close();
                stmt.close();
                releaseConnection(cr);
                throw new TransactionNotFoundException("No transaction found for identifier \"" + identifier + "\"");
            }

            ColumnMap map = rsToMap(rs);
            rs.close();
            stmt.close();
            releaseConnection(cr);
            t = create();
            populate(map, t);
        } catch (SQLException e) {
            throw new GeneralException("Error getting transaction with identifier \"" + identifier + "\"", e);
        }
        return t;
    }

    public V get(AuthorizationGrant tempCred) {
        try {
            V t = getTransaction(tempCred.getJti().toString(), getTransactionTable().getByTempCredStatement());
            return t;
        } catch (TransactionNotFoundException x) {
            return null;
        }
    }

    public V get(AccessToken accessToken) {
        try {
            V t = getTransaction(accessToken.getJti().toString(), getTransactionTable().getByAccessTokenStatement());
            return t;
        } catch (TransactionNotFoundException x) {
            return null;
        }
    }

    public V get(Verifier verifier) {
        try {
            V t = getTransaction(verifier.getToken(), getTransactionTable().getByVerifierStatement());
            return t;
        } catch (TransactionNotFoundException x) {
            return null;
        }
    }

    @Override
    public String getCreationTSField() {
        getMapConverter().getKeys();
        return null;
    }
}
