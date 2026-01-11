package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VISerializationKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.qdl_lang.variables.QDLStem;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class VIStemMC<V extends VirtualIssuer> extends MonitoredStemMC<V> {
    public VIStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    public VIStemMC(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected VISerializationKeys vik() {
        return (VISerializationKeys) keys;
    }

    /*
      String atIssuer = "at_issuer";
        String defaultKeyID = "default_key_id";
        String discoveryPath = "discovery_path";
        String issuer = "issuer";
        String jsonWebKeys = "json_web_keys";
        String title = "title";
        String valid = "valid";
     */

    @Override
    public V fromMap(QDLStem stem, V v) {
        super.fromMap(stem, v);
        if (isStringKeyOK(stem, vik().atIssuer())) {v.setAtIssuer(stem.getString(vik().atIssuer()));}
        if (isStringKeyOK(stem, vik().defaultKeyID())) {v.setDefaultKeyID(stem.getString(vik().defaultKeyID()));}
        if (isStringKeyOK(stem, vik().discoveryPath())) {v.setDiscoveryPath(stem.getString(vik().discoveryPath()));}
        if (isStringKeyOK(stem, vik().issuer())) {v.setIssuer(stem.getString(vik().issuer()));}
        if(stem.containsKey(vik().jsonWebKeys())){
             QDLStem keyStem = stem.getStem(vik().jsonWebKeys());
            JSONWebKeys keys = null;
            try {
                keys = JSONWebKeyUtil.fromJSON(keyStem.toJSON());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            v.setJsonWebKeys(keys);
        }
        if (isStringKeyOK(stem, vik().title())) {v.setTitle(stem.getString(vik().title()));}
        if (isStringKeyOK(stem, vik().valid())) {v.setValid(stem.getBoolean(vik().valid()));}

        return v;
    }

        /*
      String atIssuer = "at_issuer";
        String defaultKeyID = "default_key_id";
        String discoveryPath = "discovery_path";
        String issuer = "issuer";
        String jsonWebKeys = "json_web_keys";
        String title = "title";
        String valid = "valid";
     */

    @Override
    public QDLStem toMap(V v, QDLStem stem) {
         super.toMap(v, stem);
        setNonNullStemValue(stem, vik().atIssuer(), v.getAtIssuer());
        setNonNullStemValue(stem, vik().defaultKeyID(), v.getDefaultKeyID());
        setNonNullStemValue(stem, vik().discoveryPath(), v.getDiscoveryPath());
        setNonNullStemValue(stem, vik().issuer(), v.getIssuer());
        if (v.getJsonWebKeys()!=null && v.getJsonWebKeys().size()>0) {
            QDLStem ss = new QDLStem();
            ss.fromJSON(JSONWebKeyUtil.toJSON(v.getJsonWebKeys()));
            setNonNullStemValue(stem, vik().jsonWebKeys(), ss);
        }
        setNonNullStemValue(stem, vik().title(), v.getTitle());
        setNonNullStemValue(stem, vik().valid(), v.isValid());

        return stem;
    }

}

