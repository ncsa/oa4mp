package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  10:23 AM
 */
public interface RefreshTokenStore<V extends Identifiable> extends Store<V> {
    public OA2ServiceTransaction get(RefreshToken refreshToken);

    V get(RefreshTokenImpl refreshToken, Identifier clientID);
}
