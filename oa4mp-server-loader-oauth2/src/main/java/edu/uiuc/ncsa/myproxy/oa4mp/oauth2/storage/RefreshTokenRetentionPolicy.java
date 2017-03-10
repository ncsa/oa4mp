package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.Date;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/14 at  3:39 PM
 */
public class RefreshTokenRetentionPolicy implements RetentionPolicy {
    boolean enableDebug = false;
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

    void debug(String x){
        if(!enableDebug) return;
        System.err.println(getClass().getSimpleName() + " (" + ( new Date()) + "): " + x);

    }
    @Override
    public boolean retain(Object key, Object value) {
        debug("starting .retain method at ");
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) value;
        RefreshToken rt = st2.getRefreshToken();
        long timeout = st2.getRefreshTokenLifetime();
        if (rt == null || rt.getToken() == null) {
            debug("no RT found, using default AT policy");
            // fall back to looking at the access token timestamp. Failing that, fall back to the creation time from
            // the identifier.
            String  token;
            token = (st2.getAccessToken()==null?st2.getIdentifierString():st2.getAccessToken().getToken());
            try {
                DateUtils.checkTimestamp(token);
            } catch (InvalidTimestampException its) {
                debug("returning false - do not retain");
                return false;
            }
            debug("returning true - retain");

            return true;
        }
        // Now we have to check against the timestamp on the original and the expires in flag.
        /*
           try {
            // if there is no max timeout set, then use whatever the default is.
            if (maxTimeout <= 0) {
                DateUtils.checkTimestamp(key.toString());
            } else {
                DateUtils.checkTimestamp(key.toString(), maxTimeout);
            }
            return true;
        } catch (InvalidTimestampException its) {
            return false;
        }
         */
        try {
            if (timeout <= 0) {
                debug("timeout<=0, checking RT timestamp");
                DateUtils.checkTimestamp(rt.getToken()); // use default????

            } else {
                debug("0<timeout, checking RT timestamp against timeout=" + timeout);

                DateUtils.checkTimestamp(rt.getToken(), timeout);
            }
            debug("returning true - retain");
            return true;

        } catch (InvalidTimestampException its) {
            debug("returning false - Invalid timestamp exception, do not retain. msg=\"" + its.getMessage() + "\"");

            return false;
        }
/*
        Date creationTS = DateUtils.getDate(st2.getRefreshToken().getToken());


        if (System.currentTimeMillis() < (creationTS.getTime() + st2.getRefreshTokenLifetime())) {
            return true;
        }
        return false;
*/
    }

    @Override
    public Map getMap() {
        return rts;
    }
}
