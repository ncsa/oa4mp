package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.DSFSTransactionStore;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/12/14 at  1:21 PM
 */
public class OA2FSTStore<V extends OA2ServiceTransaction> extends DSFSTransactionStore<V> implements OA2TStoreInterface<V> {

    public OA2FSTStore(File storeDirectory, File indexDirectory,
                       IdentifiableProvider<V> idp,
                       TokenForge tokenForge,
                       MapConverter<V> cp,
                       boolean removeEmptyFiles) {
        super(storeDirectory, indexDirectory, idp, tokenForge, cp, removeEmptyFiles);
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
        if(thingie.getProxyId() != null){
            removeIndexEntry(thingie.getProxyId());
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
            if(t.getProxyId() != null){
                createIndexEntry(t.getProxyId(), t.getIdentifierString());
            }
        } catch (IOException e) {
            throw new GeneralException("Error serializing item " + t + "to file ");
        }
    }


    @Override
    public List<V> getByUsername(String username) {
        List<V> list = new ArrayList<>();
        for (Identifier id : keySet()) {
            V transaction = get(id);
            if (transaction != null ) {
                list.add(transaction);
            }
        }
        return list;
    }

    @Override
    public TokenInfoRecordMap getTokenInfo(String username) {
        TokenInfoRecordMap records = new TokenInfoRecordMap();
        for (Identifier id : keySet()) {
            V transaction = get(id);
            if (transaction != null ) {
                TokenInfoRecord tir = new TokenInfoRecord();
                tir.fromTransaction(transaction);
                records.put(tir);
            }
        }
        return records;
    }

    // Dog slow on larger stores, but there is really almost no other way than to look...
    // If you have this many transactions, switch to an SQL store where this is
    // optimized.
    @Override
    public List<RFC8628State> getPending() {
        List<RFC8628State> pending = new ArrayList<>();
        for (Identifier id : keySet()) {
            OA2ServiceTransaction transaction = get(id);
            if (transaction != null && transaction.isRFC8628Request()) {
                pending.add(transaction.getRFC8628State());
            }
        }
        return pending;
    }

    @Override
      public V getByUserCode(String userCode) {
            for (Identifier id : keySet()) {
                V transaction = get(id);
                if (transaction != null && transaction.getUserCode().equals(userCode)) {
                    return transaction;
                }
            }
            return null;
      }

    @Override
    public V getByProxyID(Identifier proxyID) {
        for (Identifier id : keySet()) {
            V transaction = getByProxyID(id);
            if (transaction != null && transaction.getProxyId().equals(id)) {
                return transaction;
            }
        }
        return null;
    }

    @Override
    public boolean hasUserCode(String userCode) {
        return getByUserCode(userCode) != null;
    }


}
