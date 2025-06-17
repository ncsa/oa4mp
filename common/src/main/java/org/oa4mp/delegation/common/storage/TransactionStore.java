package org.oa4mp.delegation.common.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * A store for delegation transactions.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 18, 2011 at  3:38:20 PM
 */
public interface TransactionStore<V extends BasicTransaction> extends Store<V> {

    V get(AuthorizationGrant authorizationGrant);

    V get(AccessToken accessToken);

    V getByProxyID(Identifier proxyID);

    MapConverter getMapConverter();

}
