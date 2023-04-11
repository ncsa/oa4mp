package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.SQLServiceTransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
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

    @Override
    public String getCreationTSField() {
        return super.getCreationTSField();
    }

    @Override
    public V getByProxyID(Identifier proxyID) {
        // Must be implemented in a subclass. Throws and exception here mostly as a head's up something is off.
        throw new NotImplementedException("Error: This is not yet implemented.");
    }
}
