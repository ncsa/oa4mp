package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

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
public class VOConverter<V extends VirtualOrganization> extends MapConverter<V> {
    public VOConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected VOSerializationKeys vok() {
        return (VOSerializationKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V vo = super.fromMap(map, v);

        vo.setCreationTS(new Date(map.getLong(vok().creationTS())));
        vo.setLastModifiedTS(new Date(map.getLong(vok().lastModifiedTS())));
        vo.setLastAccessed(new Date(map.getLong(vok().lastAccessed())));
        vo.setValid(map.getBoolean(vok().valid()));

        if (map.containsKey(vok().issuer()) && !isTrivial(map.getString(vok().issuer()))) {
            vo.setIssuer(map.getString(vok().issuer()));
        }
        if (map.containsKey(vok().atIssuer()) && !isTrivial(map.getString(vok().atIssuer()))) {
              vo.setAtIssuer(map.getString(vok().atIssuer()));
          }
        if (map.containsKey(vok().defaultKeyID()) && !isTrivial(map.getString(vok().defaultKeyID()))) {
            vo.setDefaultKeyID(map.getString(vok().defaultKeyID()));
        }
        if (map.containsKey(vok().jsonWebKeys()) && !isTrivial(map.getString(vok().jsonWebKeys()))) {
            try {
                JSONWebKeys keys = JSONWebKeyUtil.fromJSON(map.getString(vok().jsonWebKeys()));
                vo.setJsonWebKeys(keys);

            } catch (Throwable e) {
                DebugUtil.error(this, "Could not deserialize the JSON web keys for this VO.\"" + vo.getIdentifierString() + "\".", e);
            }
        }
        if (map.containsKey(vok().discoveryPath()) && !isTrivial(map.getString(vok().discoveryPath()))) {
            vo.setDiscoveryPath(map.getString(vok().discoveryPath()));
        }

        if (map.containsKey(vok().title()) && !isTrivial(map.getString(vok().title()))) {
            vo.setTitle(map.getString(vok().title()));
        }
        return vo;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        data.put(vok().valid(), value.isValid());
        data.put(vok().creationTS(), value.getCreationTS());
        data.put(vok().lastModifiedTS(), value.getLastModifiedTS());
        data.put(vok().lastAccessed(), value.getLastAccessed().getTime());
        if(!isTrivial(value.getIssuer())){
            data.put(vok().issuer(), value.getIssuer());
        }
        if(!isTrivial(value.getAtIssuer())){
              data.put(vok().atIssuer(), value.getAtIssuer());
          }
        if(!isTrivial(value.getTitle())){
            data.put(vok().title(), value.getTitle());
        }
        if(!isTrivial(value.getDefaultKeyID())){
            data.put(vok().defaultKeyID(), value.getDefaultKeyID());
        }
        if(!isTrivial(value.getDiscoveryPath())){
            data.put(vok().discoveryPath(), value.getDiscoveryPath());
        }
        if(value.getJsonWebKeys() != null){
            data.put(vok().jsonWebKeys(), JSONWebKeyUtil.toJSON(value.getJsonWebKeys()).toString());
        }
    }
}
