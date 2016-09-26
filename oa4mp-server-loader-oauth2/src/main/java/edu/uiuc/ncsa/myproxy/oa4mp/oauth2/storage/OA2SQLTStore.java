package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql.DSSQLTransactionStore;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  10:30 AM
 */
public class OA2SQLTStore<V extends OA2ServiceTransaction> extends DSSQLTransactionStore<V> implements RefreshTokenStore<V>, UsernameFindable<V> {
    public OA2SQLTStore(TokenForge tokenForge,  ConnectionPool connectionPool, Table table, Provider<V> idp, MapConverter converter) {
        super(tokenForge,  connectionPool, table, idp, converter);
    }

    @Override
    public V get(RefreshToken refreshToken) {
        return getTransaction(refreshToken.getToken(), ((OA2TransactionTable) getTransactionTable()).getByRefreshTokenStatement());
    }

    @Override
    public V getByUsername(String username) {
        return getTransaction(username, ((OA2TransactionTable) getTransactionTable()).getByUsernameStatement());
    }
}
