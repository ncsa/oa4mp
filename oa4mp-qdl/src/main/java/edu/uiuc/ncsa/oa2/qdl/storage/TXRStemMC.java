package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecordSerializationKeys;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/20 at  6:33 AM
 */
public class TXRStemMC<V extends TXRecord> extends StemConverter<V> {
    public TXRStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    protected TXRecordSerializationKeys kk() {
        return (TXRecordSerializationKeys) keys;
    }

    @Override
    public V fromMap(StemVariable stem, V v) {
        v = super.fromMap(stem, v);
        if (stem.containsKey(kk().audience())) {
            v.setAudience(toList(stem, kk().audience()));
        }
        if (stem.containsKey(kk().resource())) {
            v.setResource(toList(stem, kk().resource()));
        }
        if (stem.containsKey(kk().scopes())) {
            v.setScopes(toList(stem, kk().scopes()));
        }
        if (stem.containsKey(kk().isValid())) {
            v.setValid(stem.getBoolean(kk().isValid()));
        }
        if(stem.containsKey(kk().issuedAt())){
            v.setIssuedAt(stem.getLong(kk().issuedAt()));
        }
        if(stem.containsKey(kk().expiresAt())){
            v.setExpiresAt(stem.getLong(kk().expiresAt()));
        }
        if(stem.containsKey(kk().lifetime())){
            v.setLifetime(stem.getLong(kk().lifetime()));
        }
        if(isStringKeyOK(stem, kk().issuer())){
            v.setIssuer(stem.getString(kk().issuer()));
        }
        if(stem.containsKey(kk().parentID())){
            v.setParentID(BasicIdentifier.newID(stem.getString(kk().parentID())));
        }
        if(isStringKeyOK(stem, kk().tokenType())){
            v.setTokenType(stem.getString(kk().tokenType()));
        }
        return v;
    }

    @Override
    public StemVariable toMap(V v, StemVariable stem) {
        stem = super.toMap(v, stem);
        fromList(v.getAudience(), stem, kk().audience());
        fromList(v.getResource(), stem, kk().resource());
        fromList(v.getScopes(), stem, kk().scopes());
        stem.put(kk().issuedAt(), v.getIssuedAt());
        stem.put(kk().lifetime(), v.getLifetime());
        stem.put(kk().expiresAt(), v.getExpiresAt());
        if (!StringUtils.isTrivial(v.getIssuer())) {
            stem.put(kk().issuer(), v.getIssuer());
        }
        stem.put(kk().isValid(), v.isValid());
        if (v.getParentID() != null) {
            stem.put(kk().parentID(), v.getParentID().getUri().toString());
        }
        if (!StringUtils.isTrivial(v.getTokenType())) {
            stem.put(kk().tokenType(), v.getTokenType());
        }
        return stem;
    }
}
