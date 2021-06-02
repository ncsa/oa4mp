package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
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
        v.setNotifyOnNewClientCreate(getJsonUtil().getJSONValueBoolean(json, getACK().notifyOnNewClientCreate()));
        v.setIssuer(getJsonUtil().getJSONValueString(json, getACK().issuer()));
        v.setExternalVOName(getJsonUtil().getJSONValueString(json, getACK().vo()));
        v.setVirtualOrganization(BasicIdentifier.newID(getJsonUtil().getJSONValueString(json, getACK().voURI())));
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
        value.setExternalVOName(map.getString(getACK().vo()));
        try {
            value.setVirtualOrganization(BasicIdentifier.newID(map.getString(getACK().voURI())));
        }catch(Throwable t){
            throw new GeneralException("Error reading " + getACK().voURI() + " field in database: \"" + t.getMessage() + "\"");
        }

        value.setIssuer(map.getString(getACK().issuer()));
        if(map.containsKey(getACK().allowQDL())) {
            // older clients won't have this, so don't force the issue.
            value.setAllowQDL(map.getBoolean(getACK().allowQDL()));
        }
        if(map.containsKey(getACK().notifyOnNewClientCreate())){
            value.setNotifyOnNewClientCreate(map.getBoolean(getACK().notifyOnNewClientCreate()));
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
        getJsonUtil().setJSONValue(json, getACK().vo(), client.getExternalVOName());
        if(client.getVirtualOrganization() != null) {
            getJsonUtil().setJSONValue(json, getACK().voURI(), client.getVirtualOrganization().toString());
        }
        getJsonUtil().setJSONValue(json, getACK().issuer(), client.getIssuer());
        getJsonUtil().setJSONValue(json, getACK().maxClients(), client.getMaxClients());
        getJsonUtil().setJSONValue(json, getACK().allowQDL(), client.isAllowQDL());
        getJsonUtil().setJSONValue(json, getACK().notifyOnNewClientCreate(), client.isNotifyOnNewClientCreate());
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            json.put(getACK().config(), client.getConfig());
        }
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        map.put(getACK().issuer(), client.getIssuer());
        map.put(getACK().vo(), client.getExternalVOName());
        map.put(getACK().voURI(), client.getVirtualOrganization());
        map.put(getACK().maxClients(), client.getMaxClients());
        map.put(getACK().allowQDL(), client.isAllowQDL());
        map.put(getACK().notifyOnNewClientCreate(), client.isNotifyOnNewClientCreate());
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            map.put(getACK().config(), client.getConfig().toString(1)); // make it pretty at least...
        }
        super.toMap(client, map);
    }
}
