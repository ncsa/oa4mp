package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;

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

    /*
    This has to manage three types of token: Authz grants, access tokens and refresh tokens.
    It must check each in turn if one is missing. Final case if authz grants so that if a user
    waits a while before exchanging it for an access token, it is not garbage collected.
     */
    @Override
    public boolean retain(Object key, Object value) {
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) value;
        String token = null;

        //RefreshToken rt = st2.getRefreshToken();
        //long timeout = st2.getRefreshTokenLifetime();
        long timeout = -1L;
        if (st2.hasRefreshToken()) {
            RefreshTokenImpl rt = (RefreshTokenImpl) st2.getRefreshToken();
            if (rt.isOldVersion()) {
                // then the expires_in attribute is the same as the refresh token lifetime
                // Now, the RT lifetime cannot be zero (since that means no refresh token would have been made)
                // Therefore, set it correctly.
                if (st2.getRefreshTokenLifetime() <= 0) {
                    timeout = st2.getAccessTokenLifetime();
                } else {
                    timeout = st2.getRefreshTokenLifetime();
                }
            }else{
                timeout = st2.getRefreshTokenLifetime();
            }
            token = rt.getToken();
        } else {
            if (st2.hasAccessToken()) {
                token = st2.getAccessToken().getToken();
                timeout = st2.getAccessTokenLifetime();
            } else {
                // Can't be here without an authz grant.
                token = st2.getIdentifierString();
                timeout = st2.getAuthzGrantLifetime();
            }
        }
        DebugUtil.trace(this, "token = " + token + " lifetime = " + timeout);

        try {
            if (timeout <= 0) {
                DateUtils.checkTimestamp(token); // use default????
            } else {
                DateUtils.checkTimestamp(token, timeout);
            }
            return true;

        } catch (InvalidTimestampException its) {
            DebugUtil.trace(this, "Caught invalid timestamp for refresh token, lifetime = " + st2.getRefreshTokenLifetime() + ", actual timeout = " + timeout + ", msg=" + its.getMessage());
            return false;
        }


        // ***************

/*
        if (rt == null || rt.getToken() == null) {
            // fall back to looking at the access token timestamp. Failing that, fall back to the creation time from
            // the identifier.
            String token;
            token = (st2.getAccessToken() == null ? st2.getIdentifierString() : st2.getAccessToken().getToken());
            timeout = st2.getAccessTokenLifetime();
            try {
                DateUtils.checkTimestamp(token, timeout);
            } catch (InvalidTimestampException its) {
                DebugUtil.trace(this, "Caught invalid timestamp for access token = " + st2.getAccessToken() + "msg = " + its.getMessage());

                return false;
            }
            return true;
        }
*/

/*
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
*/
    }

    @Override
    public Map getMap() {
        return rts;
    }
}
