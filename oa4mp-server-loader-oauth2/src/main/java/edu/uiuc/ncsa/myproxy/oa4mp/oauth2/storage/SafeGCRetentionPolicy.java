package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;

/**
 * For retention policies that are "safe". This means that if this is enabled,
 * then each token is checked to see if it was created by the current server.
 * If not, it is retained. This is useful in the case of a shared database,
 * where each token has the server address.
 * <h3>E.g.</h3>
 * <p>
 *      If the service address is "http://test.cilogon.org" but the token starts with
 *      "https://cilogon.org" it will be skipped.
 * </p>
 * <p>Created by Jeff Gaynor<br>
 * on 1/27/21 at  2:35 PM
 */
public abstract class SafeGCRetentionPolicy implements RetentionPolicy {
    public SafeGCRetentionPolicy(String serviceAddress, boolean safeGC) {
        this.serviceAddress = serviceAddress;
        this.safeGC = safeGC;
    }

    String serviceAddress = null;
    boolean safeGC = true;

    protected boolean safeGCSkipIt(String key){
        if(safeGC){
               if(serviceAddress == null){
                   return true;
               }
               return !key.startsWith(serviceAddress);
        }
        return false; // false means to apply any policies in this component.
    }

}
