package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.BaseClientConverter;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  1:17 PM
 */
public class AdminClientConverter<V extends AdminClient> extends BaseClientConverter<V> {
    @Override
    public String getJSONComponentName() {
        return "admin";
    }

    public AdminClientConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }
    // At this point no need to override to/from map.

    protected AdminClientKeys getACK() {
        return (AdminClientKeys) keys;
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setIssuer(getJsonUtil().getJSONValueString(json, getACK().issuer()));
        v.setVirtualOrganization(getJsonUtil().getJSONValueString(json, getACK().vo()));
        return v;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);
        value.setVirtualOrganization(map.getString(getACK().vo()));
        value.setIssuer(map.getString(getACK().issuer()));
        return value;
    }

    @Override
    public void toJSON(V client, JSONObject json) {
        super.toJSON(client, json);
        getJsonUtil().setJSONValue(json, getACK().vo(), client.getVirtualOrganization());
        getJsonUtil().setJSONValue(json, getACK().issuer(), client.getIssuer());

    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        map.put(getACK().issuer(), client.getIssuer());
        map.put(getACK().vo(), client.getVirtualOrganization());
        super.toMap(client, map);
    }
}
