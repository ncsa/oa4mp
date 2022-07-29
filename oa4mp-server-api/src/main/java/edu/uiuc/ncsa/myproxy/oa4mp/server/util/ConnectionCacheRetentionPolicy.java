package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cache;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/2/16 at  11:44 AM
 */
public class ConnectionCacheRetentionPolicy implements RetentionPolicy {
    public ConnectionCacheRetentionPolicy(Cache myproxyConnectionCache, TransactionStore transactionStore) {
        this.transactionStore = transactionStore;
        map = myproxyConnectionCache;
    }

    TransactionStore transactionStore;

    public TransactionStore getTransactionStore() {
        return transactionStore;
    }

    Cache myproxyConnectionCache;
    @Override
    public boolean applies() {
        return true; // always try to use this.
    }

    @Override
    public boolean retain(Object key, Object value) {
        /*
        This gets the key for the connection and the connection itself. The most basic fact is
        that connections should not go away while there are active transactions.
         */
        Identifier identifier = (Identifier)key;
        boolean rc =  getTransactionStore().containsKey(identifier);
        return rc;
    }

    Map map = null;
    @Override
    public Map getMap() {
        return map;
    }
}
