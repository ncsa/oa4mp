package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientKeys;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONObject;

import java.net.URI;

import static org.qdl_lang.variables.StemUtility.put;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  6:21 AM
 */
public class AdminClientStemMC<V extends AdminClient> extends StemConverter<V> {
    public AdminClientStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    AdminClientKeys kk() {
        return (AdminClientKeys) keys;
    }

    @Override
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        /*
        String allowQDL = "allow_qdl";
        String config = "config";
        String issuer = "issuer";
        String maxClients = "max_clients";
        String notifyOnNewClientCreate="new_client_notify";
        String vi="vi";
        String voURI="vo_uri";
           */

        if (stem.containsKey(kk().creationTS())) {
            v.setCreationTS(toDate(stem, kk().creationTS()));
        }
        if (isStringKeyOK(stem, kk().email())) {
            v.setEmail(stem.getString(kk().email()));
        }
        if (stem.containsKey(kk().debugOn())) {
            v.setDebugOn(stem.getBoolean(kk().debugOn()));
        }
        if (stem.containsKey(kk().lastModifiedTS())) {
            v.setLastModifiedTS(toDate(stem, kk().lastModifiedTS()));
        }
        if (isStringKeyOK(stem, kk().name())) {
            v.setName(stem.getString(kk().name()));
        }
        if (isStringKeyOK(stem, kk().secret())) {
            v.setSecret(stem.getString(kk().secret()));
        }
        if (stem.containsKey(kk().jwksURI())) {
            v.setJwksURI(URI.create(stem.getString(kk().jwksURI())));
        }
        if (stem.containsKey(kk().jwks())) {
            try {
                JSONWebKeys jwks = JSONWebKeyUtil.fromJSON(stem.getStem(kk().jwks()).toJSON());
                v.setJWKS(jwks);
            } catch (Throwable e) {
                if (DebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                }
                throw new GeneralException("could not convert to JSON web key.", e);
            }
        }

        // Attributes specific to admin clients
        if (stem.containsKey(kk().allowQDL())) {
            v.setAllowQDL(stem.getBoolean(kk().allowQDL()));
        }
        if (stem.containsKey(kk().allowQDLCodeBlocks())) {
            v.setAllowQDLCodeBlocks(stem.getBoolean(kk().allowQDLCodeBlocks()));
        }
        if (stem.containsKey(kk().listUsers())) {
            v.setListUsers(stem.getBoolean(kk().listUsers()));
        }
        if (stem.containsKey(kk().listUsersInOtherClients())) {
            v.setListUsersInOtherClients(stem.getBoolean(kk().listUsersInOtherClients()));
        }
        if (stem.containsKey(kk().allowCustomIDs())) {
            v.setAllowCustomIDs(stem.getBoolean(kk().allowCustomIDs()));
        }
        if (stem.containsKey(kk().useTimestampsInIds())) {
            v.setUseTimestampInIDs(stem.getBoolean(kk().useTimestampsInIds()));
        }

        if (stem.containsKey(kk().generateIDs())) {
            v.setGenerateIDs(stem.getBoolean(kk().generateIDs()));
        }
        if (stem.containsKey(kk().idHead())) {
            v.setIdHead(URI.create(stem.getString(kk().idHead())));
        }
        if (isStringKeyOK(stem, kk().config())) {
            v.setConfig(JSONObject.fromObject(stem.getString(kk().config())));
        }

        if (stem.containsKey(kk().config())) {
            v.setConfig(JSONObject.fromObject(stem.getString(kk().config())));
        }
        if (isStringKeyOK(stem, kk().issuer())) {
            v.setIssuer(stem.getString(kk().issuer()));
        }
        if (stem.containsKey(kk().maxClients())) {
            v.setMaxClients(stem.getLong(kk().maxClients()).intValue());
        }
        if (isStringKeyOK(stem, kk().vo())) {
            v.setVirtualIssuer(BasicIdentifier.newID(stem.getString(kk().voURI())));
        }
        if (isStringKeyOK(stem, kk().voURI())) {
            v.setExternalVIName(stem.getString(kk().voURI()));
        }

        return v;
    }

    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        stem = super.toMap(v, stem);
        setNonNullStemValue(stem, kk().creationTS(), v.getCreationTS().getTime());
        setNonNullStemValue(stem, kk().email(), v.getEmail());
        put(stem, kk().debugOn(), v.isDebugOn());
        setNonNullStemValue(stem, kk().lastModifiedTS(), v.getLastModifiedTS().getTime());
        setNonNullStemValue(stem, kk().name(), v.getName());
        setNonNullStemValue(stem, kk().secret(), v.getSecret());

        put(stem, kk().allowQDL(), v.isAllowQDL());
        put(stem, kk().generateIDs(), v.isGenerateIDs());
        put(stem, kk().useTimestampsInIds(), v.isUseTimestampInIDs());
        put(stem, kk().allowCustomIDs(), v.isAllowCustomIDs());
        if (v.getIdHead() != null) {
            put(stem, kk().idHead(), v.getIdHead().toString());
        }
        put(stem, kk().listUsers(), v.isListUsers());
        put(stem, kk().listUsersInOtherClients(), v.isListUsersInOtherClients());
        if (v.getConfig() != null) {
            setNonNullStemValue(stem, kk().config(), v.getConfig().toString());
        }
        setNonNullStemValue(stem, kk().issuer(), v.getIssuer());
        put(stem, kk().maxClients(), Long.valueOf(v.getMaxClients()));
        setNonNullStemValue(stem, kk().allowQDLCodeBlocks(), v.allowQDLCodeBlocks());

        if (v.getVirtualIssuer() != null) {
            setNonNullStemValue(stem, kk().voURI(), v.getVirtualIssuer().toString());
        }
        if(v.getJwksURI() != null) {
            setNonNullStemValue(stem, kk().jwksURI(), v.getJwksURI().toString());
        }
        if (v.hasJWKS()) {
            QDLStem ss = new QDLStem();
            ss.fromJSON(JSONWebKeyUtil.toJSON(v.getJWKS()));
            setNonNullStemValue(stem, kk().jwks(), ss);
        }
        setNonNullStemValue(stem, kk().vo(), v.getExternalVIName());
        return stem;
    }

}
