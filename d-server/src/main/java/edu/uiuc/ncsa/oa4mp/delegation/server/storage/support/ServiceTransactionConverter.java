package edu.uiuc.ncsa.oa4mp.delegation.server.storage.support;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl.BasicTransactionConverter;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * Converts maps to or from server-side transactions.
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/12 at  11:59 AM
 */
public class ServiceTransactionConverter<V extends ServiceTransaction> extends BasicTransactionConverter<V> {
    public ServiceTransactionConverter(SerializationKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge) {
        super(keys, identifiableProvider, tokenForge);
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);
        value.setAuthGrantValid(map.getBoolean(getSTK().tempCredValid()));
        value.setAccessTokenValid(map.getBoolean(getSTK().accessTokenValid()));
        value.setCallback(map.getURI(getSTK().callbackUri()));
        value.setLifetime(map.getLong(getSTK().lifetime()));
        return value;
    }

    protected ServiceTransactionKeys getSTK() {
        return (ServiceTransactionKeys) getBTKeys();
    }

    @Override
    public void toMap(V v, ConversionMap<String, Object> map) {
        super.toMap(v, map);
        map.put(getSTK().tempCredValid(), v.isAuthGrantValid());
        map.put(getSTK().accessTokenValid(), v.isAccessTokenValid());
        if (v.getCallback() != null) {
            map.put(getSTK().callbackUri(), v.getCallback().toString());
        }
        map.put(getSTK().lifetime(), v.getLifetime());
    }
}
