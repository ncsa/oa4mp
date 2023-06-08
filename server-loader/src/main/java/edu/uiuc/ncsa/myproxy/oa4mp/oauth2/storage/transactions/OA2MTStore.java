package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.TokenInfoRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.TokenInfoRecordMap;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.TransactionMemoryStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  12:51 PM
 */
public class OA2MTStore<V extends OA2ServiceTransaction> extends TransactionMemoryStore<V> implements OA2TStoreInterface<V> {
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

    @Override
    public V get(AccessTokenImpl accessToken, Identifier clientID) {
        return getAtIndex().get(getSubIndexKey(accessToken.getJti().toString(), clientID));
    }

    @Override
    public V get(RefreshTokenImpl refreshToken, Identifier clientID) {
        return getRTIndex().get(getSubIndexKey(refreshToken.getJti().toString(), clientID));
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
        if(v.getProxyId()!=null){
            getProxyIDIndex().put(v.getProxyId(), v);
        }
        if(v.getAccessToken() != null){
            getAtIndex().put(getSubIndexKey(v.getAccessToken().getJti().toString(), v.getOA2Client().getIdentifier()), v);
        }
        if(v.getRefreshToken() != null){
            getRTIndex().put(getSubIndexKey(v.getRefreshToken().getJti().toString(), v.getOA2Client().getIdentifier()), v);
        }

    }

    protected String getSubIndexKey(String token, Identifier clientID){
        return DigestUtils.sha1Hex(clientID + "#" + token);
    }
    @Override
    protected void removeItem(V value) {
        super.removeItem(value);
        getRTIndex().remove(value.getRefreshToken());
        getUserIndex().remove(value.getUsername());
        getProxyIDIndex().remove(value.getProxyId());
        if(value.hasAccessToken()) {
            getAtIndex().remove(getSubIndexKey(value.getAccessToken().getJti().toString(), value.getOA2Client().getIdentifier()));
        }
        if(value.hasRefreshToken()) {
            getAtIndex().remove(getSubIndexKey(value.getRefreshToken().getJti().toString(), value.getOA2Client().getIdentifier()));
        }
    }

    @Override
    public V get(RefreshToken refreshToken) {
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
            if (transaction != null && userCode.equals(transaction.getUserCode())) {
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
