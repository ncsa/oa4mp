package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredConverter;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredKeys;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.Date;

/**
 * Converts to/from a stored (usually SQL) {@link KERecord}. Note that the
 * JSON web key does not have any dates in it. This is so they can be managed
 * independently of the key.
 * @param <V>
 */
public class KEConverter<V extends KERecord> extends MonitoredConverter<V> {
    public KEConverter(MonitoredKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    @Override
    public KESerializationKeys getKeys() {
        return (KESerializationKeys) super.getKeys();
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V client) {
        V v = super.fromMap(map, client);
        JSONWebKey jwk = null;
        if (isOK(map, getKeys().jwk())) {
            jwk = JSONWebKeyUtil.getJsonWebKey(map.getString(getKeys().jwk()));
            v.setJwk(jwk);
        }
        if (isOK(map, getKeys().alg())) v.setAlg(map.getString(getKeys().alg()));
        if (isOK(map, getKeys().isValid())) v.setValid(map.getBoolean(getKeys().isValid()));
        if (isOK(map, getKeys().exp()))  v.setExp(toDate(map.getLong(getKeys().exp())));
        if (isOK(map, getKeys().iat())) v.setIat(toDate(map.getLong(getKeys().iat())));
        if (isOK(map, getKeys().is_default())) v.setDefault(map.getBoolean(getKeys().is_default()));
        if (isOK(map, getKeys().kid())) v.setKid(map.getString(getKeys().kid()));
        if (isOK(map, getKeys().kty())) v.setKty(map.getString(getKeys().kty()));
        if (isOK(map, getKeys().nbf())) v.setNbf(toDate(map.getLong(getKeys().nbf())));
        if (isOK(map, getKeys().vi())) v.setVi(URI.create(map.getString(getKeys().vi())));
        return v;
    }

    /**
     * Does the map contain the key and corresponding value?
     * @param map
     * @param key
     * @return
     */
    boolean isOK(ConversionMap<String, Object> map, String key){
        return map.containsKey(key) && map.get(key) != null;
    }

    /**
     * Convert a (non-null) long to a date.
     * @param l
     * @return
     */
    Date toDate(Long l){ return new Date(l);}

    @Override
    public void toMap(V v, ConversionMap<String, Object> map) {
        super.toMap(v, map);
        if(v.getAlg() != null){map.put(getKeys().alg(), v.getAlg());}
        map.put(getKeys().isValid(), v.isValid);
        if(v.getExp() != null){map.put(getKeys().exp(), v.getExp().getTime());}
        if(v.getIat() != null){map.put(getKeys().iat(), v.getIat().getTime());}
        if(v.getDefault() != null){map.put(getKeys().is_default(), v.getDefault());}
        if(v.getJwk()!=null){
            JSONObject jsonObject = JSONWebKeyUtil.toJSON(v.getJwk());
            map.put(getKeys().jwk(), jsonObject.toString());
        }
        if(v.getKid() !=null){map.put(getKeys().kid(), v.getKid());}
        if(v.getKty() !=null){map.put(getKeys().kty(), v.getKty());}
        if(v.getNbf()!=null){map.put(getKeys().nbf(), v.getNbf().getTime());}
        if(v.getUse() !=null){map.put(getKeys().use(), v.getUse());}
        if(v.getVi() !=null){map.put(getKeys().vi(), v.getVi().toString());}
    }
}
