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
        // implies that this might be a legacy admin client and has a database entry that is null
        // rather than an integer. In that case, set it to the default.
        if(!json.containsKey(getACK().maxClients()) || json.get(getACK().maxClients()) == null){
            v.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS);
        }else{
            v.setMaxClients(getJsonUtil().getJSONValueInt(json, getACK().maxClients()));
        }
        return v;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);
        value.setVirtualOrganization(map.getString(getACK().vo()));
        value.setIssuer(map.getString(getACK().issuer()));
        // implies that this might be a legacy admin client and has a database entry that is null
        // rather than an integer. In that case, set it to the default.
        if(!map.containsKey(getACK().maxClients()) || map.get(getACK().maxClients()) == null){
            value.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS);
        }else {
            value.setMaxClients(map.getInteger(getACK().maxClients()));
        }
        return value;
    }

    @Override
    public void toJSON(V client, JSONObject json) {
        super.toJSON(client, json);
        getJsonUtil().setJSONValue(json, getACK().vo(), client.getVirtualOrganization());
        getJsonUtil().setJSONValue(json, getACK().issuer(), client.getIssuer());
        getJsonUtil().setJSONValue(json, getACK().maxClients(), client.getMaxClients());
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        map.put(getACK().issuer(), client.getIssuer());
        map.put(getACK().vo(), client.getVirtualOrganization());
        map.put(getACK().maxClients(), client.getMaxClients());
        super.toMap(client, map);
    }
}
