package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

import java.util.Date;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:39 PM
 */
public class RefreshTokenRetentionPolicy extends SafeGCRetentionPolicy {
    public RefreshTokenRetentionPolicy(RefreshTokenStore rts, TXStore txStore, String serviceAddress, boolean safeGC) {
        super(serviceAddress, safeGC);
        this.rts = rts;
        this.txStore = txStore;
    }

    RefreshTokenStore rts;

    TXStore txStore;

    /**
     * Always true for every element in the cache.
     *
     * @return
     */
    @Override
    public boolean applies() {
        return true;
    }

   boolean rttracing = false; // This turns on tracing of cleanup independent of the debug state or the log files.  VERY verbose

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
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) value;
        // First stop. If there are certificates then we will keep this around since the user can
        // come back to reget it.
/*        if(st2.getProtectedAsset()!=null && (st2.getProtectedAsset() instanceof MyX509Certificates)){
            if(System.currentTimeMillis() < st2.getLifetime() + st2.getAuthTime().getTime()){
                return true;
            }
        }*/
        String id = "id=" + (st2.getClient()!=null?st2.getClient().getIdentifierString():"(no id)") +
                ", trans = " + ((st2.hasAuthorizationGrant()?st2.getAuthorizationGrant().getToken():"no auth grant"));
        trace("starting check: " + id);

        if (safeGCSkipIt(key.toString())) {
            trace("safe GC skipping...");
            return true;
        }

        String token = null;
        //CIL-1121 CIL-1122. Keeping pending device flows managed to break cleaning up
        // abandoned flows.
        // Check for abandoned flows: In that case, the authz grant has expired
        // and there is a null access token.
        // CIL-1211 do not check validity of the grant since that is set asynchronously if the
        // authorization servlet has been replaced (e.g. in CILogon or proxying).
        trace("expired?" + st2.getAuthorizationGrant().isExpired() + ", at null?" +(st2.getAccessToken()==null) );
        if (st2.getAuthorizationGrant().isExpired() && (st2.getAccessToken() == null)) {
            trace("abandoned transaction: " + id);
            return false;
        }
        long timeout = -1L;
        if (st2.hasRefreshToken()) {
            RefreshTokenImpl rt = (RefreshTokenImpl) st2.getRefreshToken();
            trace("Checking refresh token: " + id);

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
            //token = rt.getToken();
            token = rt.getJti().toString();
        } else {
            trace("  Checking AT or Authz");

            if (st2.hasAccessToken()) {
                trace("  Checking access token");
                token = st2.getAccessToken().getJti().toString();
                timeout = st2.getAccessTokenLifetime();
            } else {
                trace("  Checking authz grant");
                // Can't be here without an authz grant.
                token = st2.getIdentifierString();
                timeout = st2.getAuthzGrantLifetime();
            }
        }
        trace(" timeout: " + timeout);

        try {
            if (timeout <= 0) {
                trace("  check timeout for token " + token + " with default timeout");
                DateUtils.checkTimestamp(token); // use default????
            } else {
                trace("check timeout for token " + token + " with issue date " + DateUtils.getDate(token));
                DateUtils.checkTimestamp(token, timeout);
            }
            trace(" retaining token " + token );

            return true;

        } catch (InvalidTimestampException its) {
            trace("timestamp expired");
            int parentCount = txStore.getCountByParent(st2.getIdentifier());
            trace("              parent count=" + parentCount);
            if (0 < parentCount) {
                // If there are ANY outstanding TX records, do not GC. Let the TX store
                // figure out what to keep.
                trace("tx store parent count: 0<" + parentCount + ", returning true (retain it) ");
                return true;
            }
            // edge case: Client generates a transaction (maybe very long lived refresh token) but
            // client gets deleted. Check if there is a client first or this will bomb with an NPE and
            // the transaction will never get garbage collected.
            if (st2.getClient()!=null && st2.getClient().isDebugOn()) {
                MetaDebugUtil debugUtil = MyProxyDelegationServlet.createDebugger(st2.getOA2Client());
                String msg = (new Date(System.currentTimeMillis())) + ": ***Removing token " + token + " with time out " + timeout;
                debugUtil.trace(this, msg);
            }
            trace("tx store parent count: 0, returning false (do NOT retain it) ");

            return false;
        }
    }

    @Override
    public Map getMap() {
        return rts;
    }


}
