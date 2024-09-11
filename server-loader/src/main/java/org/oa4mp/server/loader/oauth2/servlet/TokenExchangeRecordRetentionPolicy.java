package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.storage.SafeGCRetentionPolicy;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.security.core.util.DebugUtil;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/22 at  6:09 AM
 */
public class TokenExchangeRecordRetentionPolicy extends SafeGCRetentionPolicy {
    public TokenExchangeRecordRetentionPolicy(String serviceAddress, boolean safeGC) {
        super(serviceAddress, safeGC);
    }

    boolean rttracing = true; // This turns on tracing of cleanup independent of the debug state or the log fills.

    protected void trace(String x) {
        if (rttracing) {
            DebugUtil.trace(this, x);
        }
    }

    @Override
    public boolean retain(Object key, Object value) {
        TXRecord txr = (TXRecord) value;
        trace("checking tx_record " + txr.getIdentifierString());
        if (safeGCSkipIt(key.toString())) {
            trace("safe GFC, skipping...");
            return true;
        }
        // key is the identifier, values is the TXRecord
        if (System.currentTimeMillis() <= txr.getExpiresAt()) {
            return true; // so keep it.
        }
        return false;
    }

    @Override
    public Map getMap() {
        // Don't need the map for the policy, so don't set it.
        return null;
    }

    @Override
    public boolean applies() {
        return true;
    }
}
