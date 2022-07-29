package edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClientKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.JSONUtil;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONObject;

import java.text.ParseException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:58 PM
 */
public abstract class BaseClientConverter<V extends BaseClient> extends MapConverter<V> {
    public abstract String getJSONComponentName();

    public JSONUtil getJsonUtil() {
        if (jsonUtil == null) {
            jsonUtil = new JSONUtil(getJSONComponentName());
        }
        return jsonUtil;
    }

    JSONUtil jsonUtil;

    public BaseClientConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected BaseClientKeys getBKK() {
        return (BaseClientKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);
        value.setSecret(map.getString(getBKK().secret()));
        value.setName(map.getString(getBKK().name()));
        value.setCreationTS(map.getDate(getBKK().creationTS()));
        value.setLastModifiedTS(map.getDate(getBKK().lastModifiedTS()));
        value.setEmail(map.getString(getBKK().email()));
        value.setDebugOn(map.getBoolean(getBKK().debugOn()));
        return value;
    }

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);
        map.put(getBKK().secret(), client.getSecret());
        map.put(getBKK().email(), client.getEmail());
        map.put(getBKK().name(), client.getName());
        map.put(getBKK().creationTS(), client.getCreationTS());
        map.put(getBKK().lastModifiedTS(), client.getLastModifiedTS());
        map.put(getBKK().debugOn(), client.isDebugOn());
    }

    public V fromJSON(JSONObject json) {
        V v = createIfNeeded(null);
        v.setIdentifier(BasicIdentifier.newID(getJsonUtil().getJSONValueString(json, getBKK().identifier())));
        v.setSecret(getJsonUtil().getJSONValueString(json, getBKK().secret()));
        v.setName(getJsonUtil().getJSONValueString(json, getBKK().name()));
        v.setEmail(getJsonUtil().getJSONValueString(json, getBKK().email()));
        v.setDebugOn(getJsonUtil().getJSONValueBoolean(json, getBKK().debugOn()));
        String rawDate = getJsonUtil().getJSONValueString(json, getBKK().creationTS());
        if (rawDate != null) {
            try {
                v.setCreationTS(Iso8601.string2Date(rawDate).getTime());
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
        rawDate = getJsonUtil().getJSONValueString(json, getBKK().lastModifiedTS());
        if (rawDate != null) {
            try {
                v.setLastModifiedTS(Iso8601.string2Date(rawDate).getTime());
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
        return v;
    }


    public void toJSON(V client, JSONObject json) {
        if (json == null) {
            json = new JSONObject();
        }
        JSONObject content = new JSONObject();
        json.put(getJSONComponentName(), content);
        getJsonUtil().setJSONValue(json, getBKK().identifier(), client.getIdentifierString());

        getJsonUtil().setJSONValue(json, getBKK().email(), client.getEmail());
        getJsonUtil().setJSONValue(json, getBKK().name(), client.getName());
        getJsonUtil().setJSONValue(json, getBKK().secret(), client.getSecret());
        getJsonUtil().setJSONValue(json, getBKK().debugOn(), client.isDebugOn());
        if (client.getCreationTS() != null) {
            getJsonUtil().setJSONValue(json, getBKK().creationTS(), Iso8601.date2String(client.getCreationTS()));
        }
        if (client.getLastModifiedTS() != null) {
            getJsonUtil().setJSONValue(json, getBKK().lastModifiedTS(), Iso8601.date2String(client.getLastModifiedTS()));
        }
    }


}
