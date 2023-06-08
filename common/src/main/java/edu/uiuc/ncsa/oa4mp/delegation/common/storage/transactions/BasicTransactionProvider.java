package edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/12 at  4:23 PM
 */
public class BasicTransactionProvider<V extends BasicTransaction> extends IdentifiableProviderImpl<V> {
    public BasicTransactionProvider(IdentifierProvider<Identifier> idProvider) {
        super(idProvider);
    }

    @Override
    public V get(boolean createNewIdentifier) {
        return (V) new BasicTransaction(createNewId(createNewIdentifier));
    }

}
