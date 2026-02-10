package org.oa4mp.delegation.common.storage.clients;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredConverter;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.oa4mp.delegation.common.storage.JSONUtil;

import java.net.URI;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:58 PM
 */
public class BaseClientConverter<V extends BaseClient> extends MonitoredConverter<V> {
    // public  String getJSONComponentName(){return null;}
    public String getJSONComponentName() {
        return "client";
    }

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
        if (map.containsKey(getBKK().jwksURI())) {
            value.setJwksURI(map.getURI(getBKK().jwksURI()));
        }
        if (map.containsKey(getBKK().state()) && map.get(getBKK().state()) != null) {
            JSONObject jsonObject = JSONObject.fromObject(map.getString(getBKK().state()));
            value.setState(jsonObject);
        }
        // database may report this as being null. Do not propagate it along.
        if (map.containsKey(getBKK().jwks()) && map.get(getBKK().jwks()) != null) {
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
        if (map.containsKey(getBKK().rfc7523Client())) {
            value.setServiceClient(map.getBoolean(getBKK().rfc7523Client()));
        }
        if (map.containsKey(getBKK().rfc7523ClientUsers()) && map.get(getBKK().rfc7523ClientUsers()) != null) {
            value.setServiceClientUsers(jsonArrayToCollection(map, getBKK().rfc7523ClientUsers()));
        } else {
            JSONArray array = new JSONArray();
            array.add("*");
            value.setServiceClientUsers(array);
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
        if (client.getState() != null) {
            map.put(getBKK().state(), client.getState().toString());
        }
        if (client.hasJWKS()) {
            // Webkeys are stored as a serialized JSON string.
            map.put(getBKK().jwks(), JSONWebKeyUtil.toJSON(client.getJWKS()).toString());
        }
        if (client.hasJWKSURI()) {
            map.put(getBKK().jwksURI(), client.getJwksURI().toString());
        }
        map.put(getBKK().rfc7523Client(), client.isServiceClient());
        if (client.hasServiceClientUsers()) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(client.getServiceClientUsers());
            map.put(getBKK().rfc7523ClientUsers(), jsonArray.toString());
        } else {
            JSONArray jsonArray = new JSONArray();
            jsonArray.add("*");
            map.put(getBKK().rfc7523ClientUsers(), jsonArray.toString());
        }
    }

    /**
     * Assumes client JSON is an object of the form {"client":JSONObject} and searches the object as client.key
     *
     * @param json
     * @return
     */
    public V fromJSON(JSONObject json) {
        V v = createIfNeeded(null);
        v.setIdentifier(BasicIdentifier.newID(getJsonUtil().getJSONValueString(json, getBKK().identifier())));
        v.setSecret(getJsonUtil().getJSONValueString(json, getBKK().secret()));
        v.setName(getJsonUtil().getJSONValueString(json, getBKK().name()));
        v.setEmail(getJsonUtil().getJSONValueString(json, getBKK().email()));
        v.setDebugOn(getJsonUtil().getJSONValueBoolean(json, getBKK().debugOn()));
        v.setServiceClient(getJsonUtil().getJSONValueBoolean(json, getBKK().rfc7523Client()));
        if (json.containsKey(getBKK().state())) {
            v.setState(JSONObject.fromObject(json.getJSONObject(getBKK().state())));
        }
        if (json.containsKey(getBKK().rfc7523ClientUsers())) {
            v.setServiceClientUsers(getJsonUtil().getJSONArray(json, getBKK().rfc7523ClientUsers()));
        }
        String jwksuri = getJsonUtil().getJSONValueString(json, getBKK().jwksURI());
        if (jwksuri != null) {
            v.setJwksURI(URI.create(jwksuri));
        }
        JSONObject keys = getJsonUtil().getJSONObject(json, getBKK().jwks());
        if (keys != null) {
            try {
                v.setJWKS(jwkUtil2.fromJSON(keys));
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
        Object raw = getJsonUtil().getJSONValue(json, getBKK().creationTS());
        if (raw instanceof Long) {
            v.setCreationTS(new Date((Long) raw));
        } else {
            if (raw != null) {
                if (raw instanceof String) {
                    try {
                        v.setCreationTS(Iso8601.string2Date((String) raw).getTime());
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }

                } else {
                    throw new IllegalArgumentException("Unknown date format " + raw);
                }
            }

        }
        raw = getJsonUtil().getJSONValue(json, getBKK().lastModifiedTS());
        if (raw instanceof Long) {
            v.setLastModifiedTS(new Date((Long) raw));
        } else {
            if (raw != null) {
                if (raw instanceof String) {
                    try {
                        v.setLastModifiedTS(Iso8601.string2Date((String) raw).getTime());
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }

                } else {
                    throw new IllegalArgumentException("Unknown date format " + raw);
                }
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
        getJsonUtil().setJSONValue(json, getBKK().rfc7523Client(), client.isServiceClient());
        getJsonUtil().setJSONValue(json, getBKK().rfc7523ClientUsers(), client.getServiceClientUsers());
        if (client.getState() != null) {
            getJsonUtil().setJSONValue(json, getBKK().state(), client.getState());
        }
        if (client.hasJWKSURI()) {
            getJsonUtil().setJSONValue(json, getBKK().jwksURI(), client.getJwksURI().toString());
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
