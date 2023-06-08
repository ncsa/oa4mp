package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.FSTransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/3/11 at  12:49 PM
 */
public class DSFSTransactionStore<V extends OA4MPServiceTransaction> extends FSTransactionStore<V> {
    public DSFSTransactionStore(File file,
                                IdentifiableProvider<V> idp,
                                TokenForge tokenForge,
                                MapConverter<V> cp,
                                boolean removeEmptyFiles) {
        super(file, idp, tokenForge, cp, removeEmptyFiles);
    }

    public DSFSTransactionStore(File storeDirectory,
                                File indexDirectory,
                                IdentifiableProvider<V> idp,
                                TokenForge tokenForge,
                                MapConverter<V> cp,
                                boolean removeEmptyFiles) {
        super(storeDirectory, indexDirectory, idp, tokenForge, cp, removeEmptyFiles);                                                                 }

    @Override
    public List<V> getMostRecent(int n, List<String> attributes) {
        return null;
    }

    // This should ALWAYS be overridden since at this point in the inheritance hierarchy it
    // isn't aware of OA2 service transactions.
    @Override
    public V getByProxyID(Identifier proxyID) {
        throw new NotImplementedException("Error: This is not yet implemented for cache");
    }
}
