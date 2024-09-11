package org.oa4mp.server.api.admin.transactions;

import org.oa4mp.server.api.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import org.oa4mp.delegation.common.storage.transactions.FSTransactionStore;
import org.oa4mp.delegation.common.token.TokenForge;
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
                                boolean removeEmptyFiles,
                                boolean removeFailedFiles) {
        super(file, idp, tokenForge, cp, removeEmptyFiles,removeFailedFiles);
    }

    public DSFSTransactionStore(File storeDirectory,
                                File indexDirectory,
                                IdentifiableProvider<V> idp,
                                TokenForge tokenForge,
                                MapConverter<V> cp,
                                boolean removeEmptyFiles,
                                boolean removeFailedFiles) {
        super(storeDirectory, indexDirectory, idp, tokenForge, cp, removeEmptyFiles,removeFailedFiles);
    }

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
