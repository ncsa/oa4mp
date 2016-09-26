package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.storage.SQLServiceTransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;

/**
 * This merely exists since the superclass is abstract.
 * <p>Created by Jeff Gaynor<br>
 * on May 19, 2011 at  10:12:56 AM
 */
public class DSSQLTransactionStore<V extends OA4MPServiceTransaction> extends SQLServiceTransactionStore<V> {
    public DSSQLTransactionStore(TokenForge tokenForge,
                                 ConnectionPool connectionPool,
                                 Table table,
                                 Provider<V> idp,
                                 MapConverter converter) {
        super(tokenForge, connectionPool, table, idp, converter);
    }
}
