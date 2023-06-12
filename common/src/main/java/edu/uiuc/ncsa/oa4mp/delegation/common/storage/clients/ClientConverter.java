package edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.util.Collection;

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
        if (map.containsKey(getCK().rfc7523Client())) {
            value.setServiceClient(map.getBoolean(getCK().rfc7523Client()));
        }
        if (map.containsKey(getCK().rfc7523ClientUsers()) && map.get(getCK().rfc7523ClientUsers())!=null) {
            value.setServiceClientUsers(jsonArrayToCollection(map, getCK().rfc7523ClientUsers()));
        } else {
            JSONArray array = new JSONArray();
            array.add("*");
            value.setServiceClientUsers(array);
        }
        return value;
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);
        map.put(getCK().homeURL(), client.getHomeUri());
        map.put(getCK().errorURL(), client.getErrorUri());
        map.put(getCK().proxyLimited(), client.isProxyLimited());
        map.put(getCK().rfc7523Client(), client.isServiceClient());
        if (client.hasServiceClientUsers()) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(client.getServiceClientUsers());
            map.put(getCK().rfc7523ClientUsers(), jsonArray.toString());
        } else {
            JSONArray jsonArray = new JSONArray();
            jsonArray.add("*");
            map.put(getCK().rfc7523ClientUsers(), jsonArray);
        }
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setHomeUri(getJsonUtil().getJSONValueString(json, getCK().homeURL()));
        v.setErrorUri(getJsonUtil().getJSONValueString(json, getCK().errorURL()));
        v.setProxyLimited(getJsonUtil().getJSONValueBoolean(json, getCK().proxyLimited()));
        v.setServiceClient(getJsonUtil().getJSONValueBoolean(json, getCK().rfc7523Client()));
        if (json.containsKey(getCK().rfc7523ClientUsers())) {
               v.setServiceClientUsers(getJsonUtil().getJSONArray(json, getCK().rfc7523ClientUsers()));
           }
        return v;
    }

    @Override
    public void toJSON(V v, JSONObject json) {
        super.toJSON(v, json);
        getJsonUtil().setJSONValue(json, getCK().homeURL(), v.getHomeUri());
        getJsonUtil().setJSONValue(json, getCK().errorURL(), v.getErrorUri());
        getJsonUtil().setJSONValue(json, getCK().proxyLimited(), v.isProxyLimited());
        getJsonUtil().setJSONValue(json, getCK().rfc7523Client(), v.isServiceClient());
        getJsonUtil().setJSONValue(json, getCK().rfc7523ClientUsers(), v.getServiceClientUsers());

    }

    protected Collection<String> jsonArrayToCollection(ConversionMap<String, Object> map, String key) {
        JSONArray json;
        try {
            json = (JSONArray) JSONSerializer.toJSON(map.get(key));
        } catch (Throwable t) {
            t.printStackTrace();
            throw t;
        }
        Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(json);
        return zzz;
    }
}
