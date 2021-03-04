package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:39 PM
 */
public class RefreshTokenRetentionPolicy extends SafeGCRetentionPolicy {
    public RefreshTokenRetentionPolicy(RefreshTokenStore rts, String serviceAddress, boolean safeGC) {
        super(serviceAddress, safeGC);
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

    boolean rttracing = false; // This turns on tracing of cleanup independent of the debug state or the log fills.

    protected void trace(String x) {
        if (rttracing) {
            DebugUtil.trace(this, x);
        }
    }

    /*
    This has to manage three types of token: Authz grants, access tokens and refresh tokens.
    It must check each in turn if one is missing. Final case if authz grants so that if a user
    waits a while before exchanging it for an access token, it is not garbage collected.
     */
    @Override
    public boolean retain(Object key, Object value) {
        if (safeGCSkipIt(key.toString())) {
            return true;
        }
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) value;
        String token = null;

        //RefreshToken rt = st2.getRefreshToken();
        //long timeout = st2.getRefreshTokenLifetime();
        long timeout = -1L;
        if (st2.hasRefreshToken()) {
            RefreshTokenImpl rt = (RefreshTokenImpl) st2.getRefreshToken();
            trace("Checking refresh token");

            if (rt.isOldVersion()) {
                // then the expires_in attribute is the same as the refresh token lifetime
                // Now, the RT lifetime cannot be zero (since that means no refresh token would have been made)
                // Therefore, set it correctly.
                if (st2.getRefreshTokenLifetime() <= 0) {
                    OA2Client oa2Client = (OA2Client) st2.getClient();
                    if (0 < oa2Client.getRtLifetime()) {
                        timeout = oa2Client.getRtLifetime(); // used to be authoritative in version < 5.0
                    }
                } else {
                    timeout = st2.getRefreshTokenLifetime(); // it was set at some point
                }
            } else {
                timeout = st2.getRefreshTokenLifetime();
            }
            token = rt.getToken();
        } else {

            if (st2.hasAccessToken()) {
                trace("Checking access token");
                token = st2.getAccessToken().getToken();
                timeout = st2.getAccessTokenLifetime();
            } else {
                trace("Checking authz grant");
                // Can't be here without an authz grant.
                token = st2.getIdentifierString();
                timeout = st2.getAuthzGrantLifetime();
            }
        }
        try {
            if (timeout <= 0) {
                DateUtils.checkTimestamp(token); // use default????
            } else {
                DateUtils.checkTimestamp(token, timeout);
            }
            return true;

        } catch (InvalidTimestampException its) {

            trace("***Removing token " + token + " with time out " + timeout + " at " + System.currentTimeMillis());

            return false;
        }


    }

    @Override
    public Map getMap() {
        return rts;
    }
}
