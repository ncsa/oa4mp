package edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.ClientKeys;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/13/12 at  3:48 PM
 */
public class ClientConverter<V extends Client> extends BaseClientConverter<V> {
    @Override
    public String getJSONComponentName() {
        return "client";
    }

    public ClientConverter(IdentifiableProvider<V> identifiableProvider) {
        this(new ClientKeys(), identifiableProvider);
    }

    public ClientConverter(ClientKeys keys, IdentifiableProvider<V> identifiableProvider) {
        super(keys, identifiableProvider);
    }

    protected ClientKeys getCK() {
        return (ClientKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);

        value.setHomeUri(map.getString(getCK().homeURL()));
        value.setErrorUri(map.getString(getCK().errorURL()));
        value.setProxyLimited(map.getBoolean(getCK().proxyLimited()));
        return value;
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);
        map.put(getCK().homeURL(), client.getHomeUri());
        map.put(getCK().errorURL(), client.getErrorUri());
        map.put(getCK().proxyLimited(), client.isProxyLimited());
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setHomeUri(getJsonUtil().getJSONValueString(json,getCK().homeURL()));
        v.setErrorUri(getJsonUtil().getJSONValueString(json,getCK().errorURL()));
        v.setProxyLimited(getJsonUtil().getJSONValueBoolean(json,getCK().proxyLimited()));

        return v;
    }

    @Override
    public void toJSON(V v, JSONObject json) {
        super.toJSON(v, json);
        getJsonUtil().setJSONValue(json, getCK().homeURL(), v.getHomeUri());
        getJsonUtil().setJSONValue(json, getCK().errorURL(), v.getErrorUri());
        getJsonUtil().setJSONValue(json, getCK().proxyLimited(), v.isProxyLimited());
    }
}
