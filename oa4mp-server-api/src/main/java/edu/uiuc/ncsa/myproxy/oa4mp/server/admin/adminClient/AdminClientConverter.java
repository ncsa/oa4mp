package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
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
        v.setVirtualOrganization(BasicIdentifier.newID(getJsonUtil().getJSONValueString(json, getACK().vo())));
        v.setMaxClients(getJsonUtil().getJSONValueInt(json, getACK().maxClients()));
        v.setAllowQDL(getJsonUtil().getJSONValueBoolean(json, getACK().allowQDL()));
        JSONObject config = (JSONObject) getJsonUtil().getJSONValue(json, getACK().config());
        if (config != null) {
            v.setConfig(config);
        }
        return v;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);
        value.setVirtualOrganization(BasicIdentifier.newID(map.getString(getACK().vo())));
        value.setIssuer(map.getString(getACK().issuer()));
        if(map.containsKey(getACK().allowQDL())) {
            // older clients won't have this, so don't force the issue.
            value.setAllowQDL(map.getBoolean(getACK().allowQDL()));
        }
        // implies that this might be a legacy admin client and has a database entry that is null
        // rather than an integer. In that case, set it to the default.
        if (!map.containsKey(getACK().maxClients()) || map.get(getACK().maxClients()) == null) {
            value.setMaxClients(AdminClient.DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS);
        } else {
            value.setMaxClients(map.getInteger(getACK().maxClients()));
        }
        if (map.containsKey(getACK().config())) {
            String rawCfg = map.getString(getACK().config());
            if (rawCfg != null && !rawCfg.isEmpty()) {
                value.setConfig(JSONObject.fromObject(map.getString(getACK().config())));
            } else {
                value.setConfig(new JSONObject());
            }
        }
        return value;
    }

    @Override
    public void toJSON(V client, JSONObject json) {
        super.toJSON(client, json);
        getJsonUtil().setJSONValue(json, getACK().vo(), client.getVirtualOrganization().toString());
        getJsonUtil().setJSONValue(json, getACK().issuer(), client.getIssuer());
        getJsonUtil().setJSONValue(json, getACK().maxClients(), client.getMaxClients());
        getJsonUtil().setJSONValue(json, getACK().allowQDL(), client.isAllowQDL());
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            json.put(getACK().config(), client.getConfig());
        }
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        map.put(getACK().issuer(), client.getIssuer());
        map.put(getACK().vo(), client.getVirtualOrganization());
        map.put(getACK().maxClients(), client.getMaxClients());
        map.put(getACK().allowQDL(), client.isAllowQDL());
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            map.put(getACK().config(), client.getConfig().toString(1)); // make it pretty at least...
        }
        super.toMap(client, map);
    }
}
