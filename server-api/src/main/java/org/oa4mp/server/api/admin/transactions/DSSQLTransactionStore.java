package org.oa4mp.server.api.admin.transactions;

import org.oa4mp.server.api.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import org.oa4mp.delegation.server.storage.SQLServiceTransactionStore;
import org.oa4mp.delegation.common.token.TokenForge;
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
