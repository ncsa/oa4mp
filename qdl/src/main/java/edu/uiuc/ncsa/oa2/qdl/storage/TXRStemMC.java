package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecordSerializationKeys;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/20 at  6:33 AM
 */
public class TXRStemMC<V extends TXRecord> extends StemConverter<V> {
    public TXRStemMC(MapConverter<V> mapConverter, ClientStore clientStore) {
        super(mapConverter);
        this.clientStore = clientStore;
    }
     ClientStore clientStore;
    protected TXRecordSerializationKeys kk() {
        return (TXRecordSerializationKeys) keys;
    }


    /*
      10 attributes
      String audience = "audience";
      String ersatzID = "ersatz_id";
      String expiresAt = "expires_at";
      String lifetime = "lifetime";
      String issuedAt = "issued_at";
      String issuer = "issuer";

      String isValid = "valid";
      String parentID = "parent_id";
      String resource = "resource";
      String scopes = "scopes";
      String tokenType = "token_type";
         */
    @Override
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        if (stem.containsKey(kk().audience())) {v.setAudience(toList(stem, kk().audience()));}
        if(stem.containsKey(kk().expiresAt())){v.setExpiresAt(stem.getLong(kk().expiresAt()));}
        if(stem.containsKey(kk().ersatzID())){v.setErsatzClient((OA2Client) clientStore.get(BasicIdentifier.newID(stem.getString(kk().ersatzID()))));}

        if(stem.containsKey(kk().lifetime())){v.setLifetime(stem.getLong(kk().lifetime()));}
        if(stem.containsKey(kk().issuedAt())){v.setIssuedAt(stem.getLong(kk().issuedAt()));}
        if(isStringKeyOK(stem, kk().issuer())){v.setIssuer(stem.getString(kk().issuer()));}
        // 5
        if (stem.containsKey(kk().isValid())) {v.setValid(stem.getBoolean(kk().isValid()));}
        if(stem.containsKey(kk().parentID())){v.setParentID(BasicIdentifier.newID(stem.getString(kk().parentID())));}
        if (stem.containsKey(kk().resource())) {v.setResource(toList(stem, kk().resource()));}
        if (stem.containsKey(kk().scopes())) {v.setScopes(toList(stem, kk().scopes()));}
        if(isStringKeyOK(stem, kk().tokenType())){v.setTokenType(stem.getString(kk().tokenType()));}
        // 10 attributes
        return v;
    }
    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        stem = super.toMap(v, stem);
        fromList(v.getAudience(), stem, kk().audience());
        stem.put(kk().expiresAt(), v.getExpiresAt());
        stem.put(kk().lifetime(), v.getLifetime());
        stem.put(kk().issuedAt(), v.getIssuedAt());
        if (!StringUtils.isTrivial(v.getIssuer())) {
            stem.put(kk().issuer(), v.getIssuer());
        }
        if(v.getErsatzClient()!=null) {setNonNullStemValue(stem, kk().ersatzID(), v.getErsatzClient().getIdentifierString());}

        // 5
        stem.put(kk().isValid(), v.isValid());
        if (v.getParentID() != null) {
            stem.put(kk().parentID(), v.getParentID().getUri().toString());
        }
        fromList(v.getResource(), stem, kk().resource());
        fromList(v.getScopes(), stem, kk().scopes());
        if (!StringUtils.isTrivial(v.getTokenType())) {
            stem.put(kk().tokenType(), v.getTokenType());
        }
        // 10 attributes
        return stem;
    }
}
