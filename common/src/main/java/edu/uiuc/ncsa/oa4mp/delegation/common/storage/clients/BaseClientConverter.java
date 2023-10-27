package edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.JSONUtil;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MonitoredConverter;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSONObject;

import java.net.URI;
import java.text.ParseException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:58 PM
 */
public abstract class BaseClientConverter<V extends BaseClient> extends MonitoredConverter<V> {
    public abstract String getJSONComponentName();

    public JSONUtil getJsonUtil() {
        if (jsonUtil == null) {
            jsonUtil = new JSONUtil(getJSONComponentName());
        }
        return jsonUtil;
    }

    JSONUtil jsonUtil;

    public BaseClientConverter(BaseClientKeys keys, IdentifiableProvider<V> provider) {
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
        if(map.containsKey(getBKK().jwksURI())){
            value.setJwksURI(map.getURI(getBKK().jwksURI()));
        }
        // database may report this as being null. Do not propagate it along.
        if (map.containsKey(getBKK().jwks()) && map.get(getBKK().jwks())!=null) {
            try {
                JSONWebKeys jwks = jwkUtil2.fromJSON(map.getString(getBKK().jwks()));
                value.setJWKS(jwks);
            } catch (Throwable e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new GeneralException("error getting JWKS", e);
            }
        }
        return value;
    }
    protected JWKUtil2 jwkUtil2 = new JWKUtil2();

    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);
        map.put(getBKK().secret(), client.getSecret());
        map.put(getBKK().email(), client.getEmail());
        map.put(getBKK().name(), client.getName());
        map.put(getBKK().creationTS(), client.getCreationTS());
        map.put(getBKK().lastModifiedTS(), client.getLastModifiedTS());
        map.put(getBKK().debugOn(), client.isDebugOn());
        if (client.hasJWKS()) {
            // Webkeys are stored as a serialized JSON string.
            map.put(getBKK().jwks(), JSONWebKeyUtil.toJSON(client.getJWKS()).toString());
        }
        if(client.hasJWKSURI()){
            map.put(getBKK().jwksURI(), client.getJwksURI().toString());
        }
    }

    public V fromJSON(JSONObject json) {
        V v = createIfNeeded(null);
        v.setIdentifier(BasicIdentifier.newID(getJsonUtil().getJSONValueString(json, getBKK().identifier())));
        v.setSecret(getJsonUtil().getJSONValueString(json, getBKK().secret()));
        v.setName(getJsonUtil().getJSONValueString(json, getBKK().name()));
        v.setEmail(getJsonUtil().getJSONValueString(json, getBKK().email()));
        v.setDebugOn(getJsonUtil().getJSONValueBoolean(json, getBKK().debugOn()));
        String rawDate = getJsonUtil().getJSONValueString(json, getBKK().creationTS());
        if(json.containsKey(getBKK().jwksURI())){
            v.setJwksURI(URI.create(json.getString(getBKK().jwksURI())));
        }
        if (json.containsKey(getBKK().jwks())) {
            try {
                v.setJWKS(jwkUtil2.fromJSON((JSONObject) getJsonUtil().getJSONValue(json, getBKK().jwks())));
            } catch (Throwable e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new GeneralException("error getting JWKS", e);
            }
        }
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
        if(client.hasJWKSURI()){
            getJsonUtil().setJSONValue(json, getBKK().jwksURI(),client.getJwksURI().toString());
        }
        if (client.hasJWKS()) {
            // Stash JWKS as JSON. May revisit this decision later if it does not work for some reason.
            getJsonUtil().setJSONValue(json, getBKK().jwks(), JSONWebKeyUtil.toJSON(client.getJWKS()));
        }
        if (client.getCreationTS() != null) {
            getJsonUtil().setJSONValue(json, getBKK().creationTS(), Iso8601.date2String(client.getCreationTS()));
        }
        if (client.getLastModifiedTS() != null) {
            getJsonUtil().setJSONValue(json, getBKK().lastModifiedTS(), Iso8601.date2String(client.getLastModifiedTS()));
        }
    }


}
