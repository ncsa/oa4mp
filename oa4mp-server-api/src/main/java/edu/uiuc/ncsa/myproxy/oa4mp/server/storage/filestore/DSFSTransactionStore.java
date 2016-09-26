package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.filestore;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.FSTransactionStore;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/3/11 at  12:49 PM
 */
public class DSFSTransactionStore<V extends OA4MPServiceTransaction> extends FSTransactionStore<V> {
    public DSFSTransactionStore(File file,
                                IdentifiableProvider<V> idp,
                                TokenForge tokenForge,
                                MapConverter<V> cp) {
        super(file, idp, tokenForge, cp);
    }

    public DSFSTransactionStore(File storeDirectory,
                                File indexDirectory,
                                IdentifiableProvider<V> idp,
                                TokenForge tokenForge,
                                MapConverter<V> cp) {
        super(storeDirectory, indexDirectory, idp, tokenForge, cp);                                                                 }

}
