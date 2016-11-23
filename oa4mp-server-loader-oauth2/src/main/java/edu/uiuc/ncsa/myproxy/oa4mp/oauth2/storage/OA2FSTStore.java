package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSFSTransactionStore;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/12/14 at  1:21 PM
 */
public class OA2FSTStore<V extends OA2ServiceTransaction> extends DSFSTransactionStore<V> implements RefreshTokenStore<V>, UsernameFindable<V> {

    public OA2FSTStore(File storeDirectory, File indexDirectory,
                       IdentifiableProvider<V> idp,
                       TokenForge tokenForge,
                       MapConverter<V> cp) {
        super(storeDirectory, indexDirectory, idp, tokenForge, cp);
    }

    @Override
    public V get(RefreshToken refreshToken) {
        return getIndexEntry(refreshToken.getToken());
    }

    @Override
    public V realRemove(V thingie) {
        super.realRemove(thingie);
        if (thingie.getRefreshToken() != null) {
            removeIndexEntry(thingie.getRefreshToken().getToken());
        }
        if(thingie.getUsername() != null){
            removeIndexEntry(thingie.getUsername());
        }
        return thingie;
    }

    @Override
    public void realSave(boolean checkExists, V t) {
        super.realSave(checkExists, t);
        try {
            if (t.hasRefreshToken()) {
                createIndexEntry(t.getRefreshToken().getToken(), t.getIdentifierString());
            }
            if (t.getUsername() != null) {
                createIndexEntry(t.getUsername(), t.getIdentifierString());
            }
        } catch (IOException e) {
            throw new GeneralException("Error serializing item " + t + "to file ");
        }
    }


    @Override
    public V getByUsername(String username) {
        return getIndexEntry(username);
    }
}
