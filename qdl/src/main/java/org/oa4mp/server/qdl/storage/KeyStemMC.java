package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.kordamp.json.JSONObject;
import org.oa4mp.server.loader.oauth2.storage.keys.KERecord;
import org.oa4mp.server.loader.oauth2.storage.keys.KESerializationKeys;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.QDLValue;

import java.net.URI;
import java.util.Collection;
import java.util.Date;

// Fixes https://github.com/ncsa/oa4mp/issues/304
public class KeyStemMC<V extends KERecord> extends StemConverter<V> {

    public KeyStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    public KeyStemMC(KESerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    @Override
    public KESerializationKeys getKeys() {
        return (KESerializationKeys) super.getKeys();
    }

    @Override
    public V fromMap(QDLStem stem, V v) {
        super.fromMap(stem, v);
        if (stem.containsKey(getKeys().alg())) {v.setAlg(stem.getString(getKeys().alg()));}
        if (stem.containsKey(getKeys().exp())) {v.setExp(new Date(stem.getLong(getKeys().exp())));}
        if (stem.containsKey(getKeys().iat())) {v.setIat(new Date(stem.getLong(getKeys().iat())));}
        if (stem.containsKey(getKeys().nbf())) {v.setNbf(new Date(stem.getLong(getKeys().nbf())));}
        if (stem.containsKey(getKeys().isValid())) {v.setValid(stem.getBoolean(getKeys().isValid()));}
        if (stem.containsKey(getKeys().is_default())) {v.setDefault(stem.getBoolean(getKeys().is_default()));}
        if (stem.containsKey(getKeys().kid())) {v.setKid(stem.getString(getKeys().kid()));}
        if (stem.containsKey(getKeys().kty())) {v.setKty(stem.getString(getKeys().kty()));}
        if (stem.containsKey(getKeys().use())) {v.setUse(stem.getString(getKeys().use()));}
        if (stem.containsKey(getKeys().vi())) {v.setVi(URI.create(stem.getString(getKeys().vi())));}
        if(stem.containsKey(getKeys().jwk())){
            // JWK is a stem
            QDLStem jwk = stem.getStem(getKeys().jwk());
            try {
                JSONWebKeys x = JSONWebKeyUtil.fromJSON(jwk.toJSON());
                Collection<JSONWebKey> cc = x.values();
                if(cc.size() > 1){
                    throw new GeneralException("More than one JSON webkey found. Each record contains exactly one");
                }
                v.setJwk(cc.iterator().next());
            } catch (Exception e) {
                throw new GeneralException(e);
            }
        }
        return v;
    }
    /*
        protected String alg = "alg";
        protected String exp = "exp";
        protected String iat = "iat";
        protected String isValid = "is_valid";
        protected String is_default = "is_default";
        protected String jwk = "jwk";
        protected String kid = "kid";
        protected String kty = "kty";
        protected String nbf = "nbf";
        protected String use = "key_use"; // can't set it top 'use' since reserved SQL keyword
        protected String vi = "vi";
     */
    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        super.toMap(v, stem);
        setNonNullStemValue(stem, getKeys().alg(), v.getAlg());
        setNonNullStemValue(stem, getKeys().exp(), v.getExp());
        setNonNullStemValue(stem, getKeys().iat(), v.getIat());
        setNonNullStemValue(stem, getKeys().isValid(), v.getValid());
        setNonNullStemValue(stem, getKeys().is_default(), v.getDefault());
        setNonNullStemValue(stem, getKeys().kid(), v.getKid());
        setNonNullStemValue(stem, getKeys().kty(), v.getKty());
        setNonNullStemValue(stem, getKeys().nbf(), v.getNbf());
        setNonNullStemValue(stem, getKeys().use(), v.getUse());
        setNonNullStemValue(stem, getKeys().vi(), v.getVi().toString());
        if(v.getJwk() != null) {
            QDLStem a = new QDLStem();
            JSONObject jwk = new JSONObject();
            jwk.putAll(v.getJwk().getJOSEJWK().toJSONObject());
            a.fromJSON(jwk);
            stem.put(getKeys().jwk(), QDLValue.asQDLValue(a));
        }
        return stem;
    }
}
