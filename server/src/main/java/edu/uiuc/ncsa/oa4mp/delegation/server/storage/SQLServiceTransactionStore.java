package edu.uiuc.ncsa.oa4mp.delegation.server.storage;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.SQLBaseTransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.security.core.exceptions.UninitializedException;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 12, 2010 at  9:52:58 AM
 */
public abstract class SQLServiceTransactionStore<V extends ServiceTransaction> extends SQLBaseTransactionStore<V> {
    public static final String DEFAULT_TABLENAME = "transactions";


    protected SQLServiceTransactionStore(TokenForge tokenForge,
                                         ConnectionPool connectionPool,
                                         Table table,
                                         Provider<V> idp,
                                         MapConverter converter) {
        super(tokenForge, connectionPool, table, idp, converter);
    }

    public HashMap<String, ServiceTransaction> getCreatedTransactions() {
        if (createdTransactions == null) {
            createdTransactions = new HashMap<String, ServiceTransaction>();
        }
        return createdTransactions;
    }


    HashMap<String, ServiceTransaction> createdTransactions;

    public void register(V t) {
        if (t.getIdentifierString() == null) {
            throw new UninitializedException("Error: There is no identifier for this transaction");
        }
        super.register(t);
        getCreatedTransactions().remove(t.getIdentifier());
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[table=" + getTable() + "]";
    }
}
