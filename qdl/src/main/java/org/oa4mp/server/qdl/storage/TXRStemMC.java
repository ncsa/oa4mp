package org.oa4mp.server.qdl.storage;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecordSerializationKeys;
import org.oa4mp.server.loader.oauth2.storage.tx.TXStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONObject;

import static org.qdl_lang.variables.StemUtility.put;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/20 at  6:33 AM
 */
public class TXRStemMC<V extends TXRecord> extends StemConverter<V> {
    public TXRStemMC(MapConverter<V> mapConverter,
                     TXStore txStore,
                     ClientStore clientStore) {
        super(mapConverter);
        this.clientStore = clientStore;
        this.txStore = txStore;
    }
     ClientStore clientStore;
    TXStore txStore;
    protected TXRecordSerializationKeys kk() {
        return (TXRecordSerializationKeys) keys;
    }


    /*
      12 attributes
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
      String tokenType = "token";
         */
    @Override
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        if (stem.containsKey(kk().audience())) {v.setAudience(toList(stem, kk().audience()));}
        if(stem.containsKey(kk().expiresAt())){v.setExpiresAt(stem.getLong(kk().expiresAt()));}
        if(stem.containsKey(kk().ersatzID())){v.setErsatzClient((OA2Client) clientStore.get(BasicIdentifier.newID(stem.getString(kk().ersatzID()))));}
   //     if(stem.containsKey(kk().previousTXRecord())){v.setPreviousTXR((TXRecord)txStore.get(BasicIdentifier.newID(stem.getString(kk().previousTXRecord()))));};
        if(stem.containsKey(kk().token())){v.setToken((JSONObject) stem.getStem(kk().token()).toJSON());};
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
        put(stem,kk().expiresAt(), v.getExpiresAt());
        put(stem,kk().lifetime(), v.getLifetime());
        put(stem,kk().issuedAt(), v.getIssuedAt());
        if (!StringUtils.isTrivial(v.getIssuer())) {
            put(stem,kk().issuer(), v.getIssuer());
        }
        if(v.getErsatzClient()!=null) {setNonNullStemValue(stem, kk().ersatzID(), v.getErsatzClient().getIdentifierString());}
        // 5
        put(stem,kk().isValid(), v.isValid());
        if (v.getParentID() != null) {
            put(stem,kk().parentID(), v.getParentID().getUri().toString());
        }
        fromList(v.getResource(), stem, kk().resource());
        fromList(v.getScopes(), stem, kk().scopes());
        if (!StringUtils.isTrivial(v.getTokenType())) {
            put(stem,kk().tokenType(), v.getTokenType());
        }
        // 10 attributes
        return stem;
    }
}
