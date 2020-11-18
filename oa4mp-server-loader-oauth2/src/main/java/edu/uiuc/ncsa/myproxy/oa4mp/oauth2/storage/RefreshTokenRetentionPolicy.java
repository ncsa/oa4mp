package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:39 PM
 */
public class RefreshTokenRetentionPolicy implements RetentionPolicy {
    public RefreshTokenRetentionPolicy(RefreshTokenStore rts) {
        this.rts = rts;
    }

    RefreshTokenStore rts;

    /**
     * Always true for every element in the cache.
     *
     * @return
     */
    @Override
    public boolean applies() {
        return true;
    }

    @Override
    public boolean retain(Object key, Object value) {
        DebugUtil.trace(this, "retain start");
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) value;
        RefreshToken rt = st2.getRefreshToken();
        long timeout = st2.getRefreshTokenLifetime();
        DebugUtil.trace(this, "timeout=" + timeout);

        if (rt == null || rt.getToken() == null) {
            // fall back to looking at the access token timestamp. Failing that, fall back to the creation time from
            // the identifier.
            String  token;
            token = (st2.getAccessToken()==null?st2.getIdentifierString():st2.getAccessToken().getToken());
            try {
                DateUtils.checkTimestamp(token);
            } catch (InvalidTimestampException its) {
                DebugUtil.trace(this, "Caught invalid timestamp for access token = " + st2.getAccessToken() + "msg = " + its.getMessage() );

                return false;
            }
            return true;
        }

        try {
            if (timeout <= 0) {
                DateUtils.checkTimestamp(rt.getToken()); // use default????
            } else {
                DateUtils.checkTimestamp(rt.getToken(), timeout);
            }
            return true;

        } catch (InvalidTimestampException its) {
            DebugUtil.trace(this, "Caught invalid timestamp for refresh token, lifetime = " + st2.getRefreshTokenLifetime() + ", actual timeout = " + timeout + ", msg=" + its.getMessage());
            return false;
        }
    }

    @Override
    public Map getMap() {
        return rts;
    }
}
