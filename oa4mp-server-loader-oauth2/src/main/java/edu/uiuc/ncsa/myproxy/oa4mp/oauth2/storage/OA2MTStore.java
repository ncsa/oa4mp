package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.storage.impl.TransactionMemoryStore;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  12:51 PM
 */
public class OA2MTStore<V extends OA2ServiceTransaction> extends TransactionMemoryStore<V> implements RefreshTokenStore<V>, UsernameFindable<V>, RFC8628Store<V> {
    public OA2MTStore(IdentifiableProvider identifiableProvider) {
        super(identifiableProvider);
    }

    TokenIndex rtIndex;
    TokenIndex userIndex;

    public TokenIndex getRTIndex() {
        if (rtIndex == null) {
            rtIndex = new TokenIndex();
        }
        return rtIndex;
    }

    public TokenIndex getUserIndex() {
        if (userIndex == null) {
            userIndex = new TokenIndex();
        }
        return userIndex;
    }

    @Override
    protected void updateIndices(V v) {
        super.updateIndices(v);
        if (v.getRefreshToken() != null) {
            getRTIndex().put(v.getRefreshToken().getToken(), v);
        }
        if (v.getUsername() != null) {
            getUserIndex().put(v.getUsername(), v);
        }
    }

    @Override
    protected void removeItem(V value) {
        super.removeItem(value);
        getRTIndex().remove(value.getRefreshToken());
        getUserIndex().remove(value.getUsername());
    }

    @Override
    public OA2ServiceTransaction get(RefreshToken refreshToken) {
        return getRTIndex().get(refreshToken.getToken());
    }

    @Override
    public List<V> getByUsername(String username) {
        List<V> list = new ArrayList<>();
        for (Identifier id : keySet()) {
            V transaction = get(id);
            if (transaction != null) {
                list.add(transaction);
            }
        }
        return list;
    }


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
    public boolean hasUserCode(String userCode) {
        return getByUserCode(userCode) != null;
    }
}
