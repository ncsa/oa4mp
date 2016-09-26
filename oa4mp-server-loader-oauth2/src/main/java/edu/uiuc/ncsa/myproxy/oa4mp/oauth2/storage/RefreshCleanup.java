package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.Set;
import java.util.TreeSet;

/**
 * A very specific cleanup for store that know about refresh tokens. This returns the set of
 * RefreshTokens (all unique) rather than the set of primary keys, so any retention policy
 * is applied to those instead.
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:31 PM
 */
public class RefreshCleanup<K, V> extends Cleanup<K, V> {
    RefreshTokenStore rts;

    public RefreshCleanup(RefreshTokenStore refreshTokenStore, MyLoggingFacade logger) {
        super(logger);
        this.rts = refreshTokenStore;
    }

    @Override
    public Set<K> getSortedKeys() {
        TreeSet targetList = new TreeSet<>();
        for (Object key : rts.keySet()) {
            OA2ServiceTransaction st2 = (OA2ServiceTransaction) rts.get(key);
            targetList.add(st2.getRefreshToken());
        }
        return targetList;
    }
}
