package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransactionProvider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/12 at  4:40 PM
 */
public class DSTransactionProvider<V extends OA4MPServiceTransaction> extends ServiceTransactionProvider<V> {

    public DSTransactionProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);
    }

    public DSTransactionProvider() {
        super(new OA4MPIdentifierProvider(OA4MPIdentifierProvider.TRANSACTION_ID));
    }

    @Override
    public V get(boolean createNewIdentifier) {
        return (V) new OA4MPServiceTransaction(createNewId(createNewIdentifier));
    }
}
