package org.oa4mp.server.loader.oauth2.storage.transactions;

import org.oa4mp.server.loader.oauth2.servlet.RFC8628State;
import org.oa4mp.server.loader.oauth2.storage.RFC8628Store;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenStore;
import org.oa4mp.server.loader.oauth2.storage.TokenInfoRecordMap;
import org.oa4mp.server.loader.oauth2.storage.UsernameFindable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.RefreshToken;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/16/22 at  6:58 AM
 */
public interface OA2TStoreInterface<V extends OA2ServiceTransaction> extends Store<V>, TransactionStore<V>, RFC8628Store<V>, RefreshTokenStore<V>, UsernameFindable<V> {
    @Override
    V get(RefreshToken refreshToken);

    V get(AccessTokenImpl accessToken, Identifier clientID);

    @Override
    List<V> getByUsername(String username);

    TokenInfoRecordMap getTokenInfo(String username);

    @Override
    List<RFC8628State> getPending();

    @Override
    V getByProxyID(Identifier proxyID);

    @Override
    V getByUserCode(String userCode);

    @Override
    boolean hasUserCode(String userCode);

    List<Identifier> getByClientID(Identifier clientID);
    List<Identifier> getAllClientID();
    /**
     * Get a transaction by its ID token identifier. Note that to get the token itself,
     * you must use {@link OA2ServiceTransaction#getUserMetaData()}.
      * @param proxyID
     * @return
     */
    V getByIDTokenID(Identifier proxyID);

}
