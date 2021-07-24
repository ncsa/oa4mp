package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSSQLTransactionStore;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import javax.inject.Provider;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction.RFC862_STATE_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  10:30 AM
 */
public class OA2SQLTStore<V extends OA2ServiceTransaction> extends DSSQLTransactionStore<V> implements RFC8628Store<V>, RefreshTokenStore<V>, UsernameFindable<V> {
    public OA2SQLTStore(TokenForge tokenForge, ConnectionPool connectionPool, Table table, Provider<V> idp, MapConverter converter) {
        super(tokenForge, connectionPool, table, idp, converter);
    }

    @Override
    public V get(RefreshToken refreshToken) {
        return getByRefreshToken(refreshToken);
    }

    public V getByRefreshToken(RefreshToken refreshToken) {
        String identifier = ((RefreshTokenImpl) refreshToken).getJti().toString();
        return getTransaction(identifier, ((OA2TransactionTable) getTransactionTable()).getByRefreshTokenStatement());
    }

    @Override
    public V getByUsername(String username) {
        return getTransaction(username, ((OA2TransactionTable) getTransactionTable()).getByUsernameStatement());
    }

    /**
     * Since this is  potentially a very intensive operation run only once at startup
     * this has been tweaked to exactly let the database grab the minimum and process it here.
     * 
     * @return
     */
    @Override
    public List<RFC8628State> getPending() {
        List<RFC8628State> pending = new ArrayList<>();
        ConnectionRecord cr = getConnection();
        Connection c = cr.connection;
        OA2TransactionTable oa2TT = (OA2TransactionTable) getTable();
        try {
            PreparedStatement stmt = c.prepareStatement(oa2TT.getRFC8628());
            stmt.execute();// just execute() since executeQuery(x) would throw an exception regardless of content per JDBC spec.

            ResultSet rs = stmt.getResultSet();
            while (rs.next()) {
                String rawJSON = rs.getString(1);
                // This is buried in the transaction state. Unearth it directly
                // Makes the path from store to rfc8626 state as short as possible.
                if (!StringUtils.isTrivial(rawJSON)) {
                    JSONObject json = (JSONObject) JSONSerializer.toJSON(rawJSON);
                    JSONObject j = json.getJSONObject(RFC862_STATE_KEY);
                    RFC8628State state = new RFC8628State();
                    state.fromJSON(j);
                    pending.add(state);
                }
            }
            rs.close();
            stmt.close();
            releaseConnection(cr);
        } catch (SQLException e) {
            destroyConnection(cr);
            throw new GeneralException("Error: could not get database object", e);
        }

        return pending;
    }

}
