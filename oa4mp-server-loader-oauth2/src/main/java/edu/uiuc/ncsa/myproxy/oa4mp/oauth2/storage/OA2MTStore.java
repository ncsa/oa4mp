package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.TransactionMemoryStore;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  12:51 PM
 */
public class OA2MTStore<V extends OA2ServiceTransaction> extends TransactionMemoryStore<V> implements RefreshTokenStore<V>, UsernameFindable<V>{
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

    public TokenIndex getUserIndex(){
        if(userIndex == null){
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
        if(v.getUsername()!= null){
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
    public V getByUsername(String username) {
        return getUserIndex().get(username);
    }
}
