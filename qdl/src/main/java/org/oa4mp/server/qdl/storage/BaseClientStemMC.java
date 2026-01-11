package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.BaseClientKeys;
import org.qdl_lang.variables.QDLStem;

import java.net.URI;

import static org.qdl_lang.variables.StemUtility.put;

public class BaseClientStemMC<V extends BaseClient> extends MonitoredStemMC<V> {
    public BaseClientStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    public BaseClientStemMC(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected BaseClientKeys bck() {
        return (BaseClientKeys) keys;
    }

    /* BaseClient Keys
    String debugOn = "debug_on";
    String email = "email";
    String name = "name";
    String secret = "oauth_client_pubkey";
    String jwks = "jwks";
    String jwksURI = "jwks_uri";
    String rfc7523Client = "rfc7523_client";
    String rfc7523ClientUsers = "rfc7523_client_users";
     */
    @Override
    public V fromMap(QDLStem stem, V v) {
        super.fromMap(stem, v);
        if (stem.containsKey(bck().debugOn())) {
            v.setDebugOn(stem.getBoolean(bck().debugOn()));
        }
        if (isStringKeyOK(stem, bck().email())) {
            v.setName(stem.getString(bck().email()));
        }
        if (isStringKeyOK(stem, bck().name())) {
            v.setName(stem.getString(bck().name()));
        }
        if (isStringKeyOK(stem, bck().secret())) {
            v.setSecret(stem.getString(bck().secret()));
        }
        if (stem.containsKey(bck().jwks())) {
            try {
                JSONWebKeys jwks = JSONWebKeyUtil.fromJSON(stem.getStem(bck().jwks()).toJSON());
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
        if (stem.containsKey(bck().jwksURI())) {
            v.setJwksURI(URI.create(stem.getString(bck().jwksURI())));
        }
        if (stem.containsKey(bck().rfc7523Client())) {
            v.setServiceClient(stem.getBoolean(bck().rfc7523Client()));
        }
        if (stem.containsKey(bck().rfc7523ClientUsers())) {
            v.setServiceClientUsers(toList(stem, bck().rfc7523ClientUsers()));
        }

        return v;
    }


    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        super.toMap(v, stem);
        put(stem, bck().debugOn(), v.isDebugOn());
        setNonNullStemValue(stem, bck().email(), v.getEmail());
        setNonNullStemValue(stem, bck().name(), v.getName());
        setNonNullStemValue(stem, bck().secret(), v.getSecret());
        if (v.hasJWKS()) {
            QDLStem ss = new QDLStem();
            ss.fromJSON(JSONWebKeyUtil.toJSON(v.getJWKS()));
            setNonNullStemValue(stem, bck().jwks(), ss);
        }
        if (v.getJwksURI() != null) {
            setNonNullStemValue(stem, bck().jwksURI(), v.getJwksURI().toString());
        }

        setNonNullStemValue(stem, bck().rfc7523Client(), v.isServiceClient());
        fromList(v.getServiceClientUsers(), stem, bck().rfc7523ClientUsers());
        return stem;
    }
}
