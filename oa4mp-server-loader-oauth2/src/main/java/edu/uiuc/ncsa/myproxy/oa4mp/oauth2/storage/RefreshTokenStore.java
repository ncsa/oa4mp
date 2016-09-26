package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/14 at  10:23 AM
 */
public interface RefreshTokenStore<V extends Identifiable> extends Store<V> {
    public OA2ServiceTransaction get(RefreshToken refreshToken);
}
