package org.oa4mp.server.loader.oauth2.storage.vi;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;

import java.util.Date;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/19/21 at  3:04 PM
 */
public class VIConverter<V extends VirtualIssuer> extends MapConverter<V> {
    public VIConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected VISerializationKeys vok() {
        return (VISerializationKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V vi = super.fromMap(map, v);

        vi.setCreationTS(new Date(map.getLong(vok().creationTS())));
        vi.setLastModifiedTS(new Date(map.getLong(vok().lastModifiedTS())));

        // Fixes https://github.com/ncsa/oa4mp/issues/149
        vi.setLastAccessed(new Date(map.getLong(vok().lastAccessed())));
        vi.setValid(map.getBoolean(vok().valid()));

        if (map.containsKey(vok().issuer()) && !isTrivial(map.getString(vok().issuer()))) {
            vi.setIssuer(map.getString(vok().issuer()));
        }
        if (map.containsKey(vok().atIssuer()) && !isTrivial(map.getString(vok().atIssuer()))) {
            vi.setAtIssuer(map.getString(vok().atIssuer()));
        }
        if (map.containsKey(vok().defaultKeyID()) && !isTrivial(map.getString(vok().defaultKeyID()))) {
            vi.setDefaultKeyID(map.getString(vok().defaultKeyID()));
        }
        if (map.containsKey(vok().jsonWebKeys()) && !isTrivial(map.getString(vok().jsonWebKeys()))) {
            try {
                JSONWebKeys keys = JSONWebKeyUtil.fromJSON(map.getString(vok().jsonWebKeys()));
                vi.setJsonWebKeys(keys);

            } catch (Throwable e) {
                DebugUtil.error(this, "Could not deserialize the JSON web keys for this VI.\"" + vi.getIdentifierString() + "\".", e);
            }
        }
        if (map.containsKey(vok().discoveryPath()) && !isTrivial(map.getString(vok().discoveryPath()))) {
            vi.setDiscoveryPath(map.getString(vok().discoveryPath()));
        }

        if (map.containsKey(vok().title()) && !isTrivial(map.getString(vok().title()))) {
            vi.setTitle(map.getString(vok().title()));
        }
        return vi;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        data.put(vok().valid(), value.isValid());
        if (value.getCreationTS() != null) {
            data.put(vok().creationTS(), value.getCreationTS().getTime());
        }
        if (value.getLastModifiedTS() != null) {
            data.put(vok().lastModifiedTS(), value.getLastModifiedTS().getTime());
        }
        if (value.getLastAccessed() != null) {
            // Fixes https://github.com/ncsa/oa4mp/issues/149
            data.put(vok().lastAccessed(), value.getLastAccessed().getTime());
        }
        if (!isTrivial(value.getIssuer())) {
            data.put(vok().issuer(), value.getIssuer());
        }
        if (!isTrivial(value.getAtIssuer())) {
            data.put(vok().atIssuer(), value.getAtIssuer());
        }
        if (!isTrivial(value.getTitle())) {
            data.put(vok().title(), value.getTitle());
        }
        if (!isTrivial(value.getDefaultKeyID())) {
            data.put(vok().defaultKeyID(), value.getDefaultKeyID());
        }
        if (!isTrivial(value.getDiscoveryPath())) {
            data.put(vok().discoveryPath(), value.getDiscoveryPath());
        }
        if (value.getJsonWebKeys() != null) {
            data.put(vok().jsonWebKeys(), JSONWebKeyUtil.toJSON(value.getJsonWebKeys()).toString());
        }
    }
}
