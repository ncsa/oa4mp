package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClientConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.sf.json.JSONObject;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  1:17 PM
 */
public class AdminClientConverter<V extends AdminClient> extends BaseClientConverter<V> {
    @Override
    public String getJSONComponentName() {
        return "admin";
    }

    public AdminClientConverter(AdminClientKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }
    // At this point no need to override to/from map.

    protected AdminClientKeys getACK() {
        return (AdminClientKeys) keys;
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setListUsers(getJsonUtil().getJSONValueBoolean(json, getACK().listUsers()));
        v.setListUsersInOtherClients(getJsonUtil().getJSONValueBoolean(json, getACK().listUsersInOtherClients()));
        v.setNotifyOnNewClientCreate(getJsonUtil().getJSONValueBoolean(json, getACK().notifyOnNewClientCreate()));
        v.setIssuer(getJsonUtil().getJSONValueString(json, getACK().issuer()));
        v.setExternalVOName(getJsonUtil().getJSONValueString(json, getACK().vo()));
        v.setVirtualOrganization(BasicIdentifier.newID(getJsonUtil().getJSONValueString(json, getACK().voURI())));
        v.setMaxClients(getJsonUtil().getJSONValueInt(json, getACK().maxClients()));
        v.setAllowQDL(getJsonUtil().getJSONValueBoolean(json, getACK().allowQDL()));
        v.setGenerateIDs(getJsonUtil().getJSONValueBoolean(json, getACK().generateIDs()));
        v.setUseTimestampInIDs(getJsonUtil().getJSONValueBoolean(json, getACK().useTimestampsInIds()));
        v.setAllowCustomIDs(getJsonUtil().getJSONValueBoolean(json, getACK().allowCustomIDs()));
        if(getJsonUtil().hasKey(json,getACK().idHead())){
             v.setIdHead(URI.create(getJsonUtil().getJSONValueString(json,getACK().idHead())));
        }
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
        } catch (Throwable t) {
            throw new GeneralException("Error reading " + getACK().voURI() + " field in database: \"" + t.getMessage() + "\"");
        }

        value.setIssuer(map.getString(getACK().issuer()));
        if (map.containsKey(getACK().allowCustomIDs())) {
            // older clients won't have this, so don't force the issue.
            value.setAllowCustomIDs(map.getBoolean(getACK().allowCustomIDs()));
        }
        if (map.containsKey(getACK().generateIDs())) {
            // older clients won't have this, so don't force the issue.
            value.setGenerateIDs(map.getBoolean(getACK().generateIDs()));
        }
        if (map.containsKey(getACK().useTimestampsInIds())) {
             // older clients won't have this, so don't force the issue.
             value.setUseTimestampInIDs(map.getBoolean(getACK().useTimestampsInIds()));
         }
        if (map.containsKey(getACK().idHead()) && map.get(getACK().idHead())!=null) {
            // older clients won't have this, so don't force the issue.
            value.setIdHead(URI.create(map.getString(getACK().idHead())));
        }
        if (map.containsKey(getACK().allowQDL())) {
            // older clients won't have this, so don't force the issue.
            value.setAllowQDL(map.getBoolean(getACK().allowQDL()));
        }
        if (map.containsKey(getACK().allowQDLCodeBlocks())) {
            value.setAllowQDLCodeBlocks(map.getBoolean(getACK().allowQDLCodeBlocks()));
        }
        if (map.containsKey(getACK().notifyOnNewClientCreate())) {
            value.setNotifyOnNewClientCreate(map.getBoolean(getACK().notifyOnNewClientCreate()));
        }

        if (map.containsKey(getACK().listUsers())) {
            value.setListUsers(map.getBoolean(getACK().listUsers()));
        }

        if (map.containsKey(getACK().listUsersInOtherClients())) {
            value.setListUsersInOtherClients(map.getBoolean(getACK().listUsersInOtherClients()));
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
        if (client.getVirtualOrganization() != null) {
            getJsonUtil().setJSONValue(json, getACK().voURI(), client.getVirtualOrganization().toString());
        }
        getJsonUtil().setJSONValue(json, getACK().allowCustomIDs(), client.isAllowCustomIDs());
        getJsonUtil().setJSONValue(json, getACK().generateIDs(), client.isGenerateIDs());
        getJsonUtil().setJSONValue(json, getACK().useTimestampsInIds(), client.isUseTimestampInIDs());
        if(client.getIdHead()!=null){
            getJsonUtil().setJSONValue(json, getACK().idHead(), client.getIdHead().toString());
        }
        getJsonUtil().setJSONValue(json, getACK().issuer(), client.getIssuer());
        getJsonUtil().setJSONValue(json, getACK().maxClients(), client.getMaxClients());
        getJsonUtil().setJSONValue(json, getACK().allowQDL(), client.isAllowQDL());
        getJsonUtil().setJSONValue(json, getACK().notifyOnNewClientCreate(), client.isNotifyOnNewClientCreate());
        getJsonUtil().setJSONValue(json, getACK().listUsers(), client.isListUsers());
        getJsonUtil().setJSONValue(json, getACK().listUsersInOtherClients(), client.isListUsersInOtherClients());
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
        map.put(getACK().allowQDLCodeBlocks(), client.allowQDLCodeBlocks());
        map.put(getACK().generateIDs(), client.isGenerateIDs());
        map.put(getACK().allowCustomIDs(), client.isAllowCustomIDs());
        map.put(getACK().useTimestampsInIds(), client.isUseTimestampInIDs());
        if(client.getIdHead()!=null){
            map.put(getACK().idHead(), client.getIdHead().toString());
        }
        map.put(getACK().notifyOnNewClientCreate(), client.isNotifyOnNewClientCreate());
        map.put(getACK().listUsers(), client.isListUsers());
        map.put(getACK().listUsersInOtherClients(), client.isListUsersInOtherClients());
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            map.put(getACK().config(), client.getConfig().toString(1)); // make it pretty at least...
        }
        super.toMap(client, map);
    }
}
