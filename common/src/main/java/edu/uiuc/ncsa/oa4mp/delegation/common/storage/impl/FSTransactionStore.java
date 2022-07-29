package edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.io.IOException;


/**
 * Implementation of a transaction store backed by the file system.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 28, 2010 at  3:01:10 PM
 */
public abstract class FSTransactionStore<V extends BasicTransaction> extends FileStore<V> implements TransactionStore<V> {
    protected FSTransactionStore(File storeDirectory,
                                 File indexDirectory,
                                 IdentifiableProvider<V> idp,
                                 TokenForge tokenForge,
                                 MapConverter<V> mp,
                                 boolean removeEmptyFiles) {
        super(storeDirectory, indexDirectory, idp, mp, removeEmptyFiles);
        this.tokenForge = tokenForge;
    }

    protected TokenForge tokenForge;

    public FSTransactionStore(File file,
                              IdentifiableProvider<V> idp,
                              TokenForge tokenForge,
                              MapConverter<V> mp, boolean removeEmptyFiles) {
        super(file, idp, mp, removeEmptyFiles);
        this.tokenForge = tokenForge;
    }


    /**
     * Add code to store index references to the transaction by access token, verifier and
     * authorization grant.
     *
     * @param checkExists
     * @param t
     */
    @Override
    public void realSave(boolean checkExists, V t) {
        super.realSave(checkExists, t);
        try {
            if (t.hasAuthorizationGrant()) {
                createIndexEntry(t.getAuthorizationGrant().getToken(), t.getIdentifierString());
            }
            if (t.hasAccessToken()) {
                createIndexEntry(t.getAccessToken().getToken(), t.getIdentifierString());
            }
            if (t.hasVerifier()) {
                createIndexEntry(t.getVerifier().getToken(), t.getIdentifierString());
            }
        } catch (IOException e) {
            throw new GeneralException("Error serializing item " + t + "to file ");
        }
    }

    @Override
    public V realRemove(V thingie) {
        super.realRemove(thingie);
        if (thingie.getAccessToken() != null) {
            removeIndexEntry(thingie.getAccessToken().getToken());
        }
        if (thingie.getVerifier() != null) {
            removeIndexEntry(thingie.getVerifier().getToken());
        }
        return thingie;
    }

    public V get(AuthorizationGrant authorizationGrant) {
        return getIndexEntry(authorizationGrant.getToken());
    }

    public V get(AccessToken accessToken) {
        return getIndexEntry(accessToken.getToken());
    }

    public V get(Verifier verifier) {
        return getIndexEntry(verifier.getToken());
    }

    @Override
    public MapConverter getMapConverter() {
        return converter;
    }
}
