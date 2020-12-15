package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONArray;

import java.net.URI;
import java.util.ArrayList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  9:05 AM
 */
public class TXRecordConverter<V extends TXRecord> extends MapConverter<V> {
    public TXRecordConverter(SerializationKeys keys,
                             IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected TXRecordSerializationKeys tkeys(){
        return (TXRecordSerializationKeys) getKeys();
    }
    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V txr = super.fromMap(map, v);
        if(map.containsKey(tkeys().audience()) && map.get(tkeys().audience())!=null){
            //optional. Stored as JSON array.
           JSONArray a = JSONArray.fromObject(map.getString(tkeys().audience()));
           txr.setAudience(a);
        }
        txr.setParentID(map.getIdentifier(tkeys().parentID()));
        txr.setExpiresAt(map.getLong(tkeys().expiresAt()));
        txr.setLifetime(map.getLong(tkeys().lifetime()));
        txr.setIssuedAt(map.getLong(tkeys().issuedAt()));
        txr.setTokenType(map.getString(tkeys().tokenType()));
        if(map.containsKey(tkeys().issuer()) && map.get(tkeys().issuer())!=null) {
            txr.setIssuer(map.getString(tkeys().issuer()));
        }
        if(map.containsKey(tkeys().resource()) && map.get(tkeys().resource()) != null){
            // optional
            JSONArray a = JSONArray.fromObject(map.getString(tkeys().resource()));
            ArrayList<URI> a1 = new ArrayList<>();
            for(int i = 0; i < a.size(); i++){
                a1.add(URI.create(a.getString(i)));
            }
            a1.addAll(a);
           // You generally do NOT want a JSONArray of URIs since the library will turn each of them in to JSON
            // objects (very complex) and completey screw up trying to use them.
            txr.setResource(a1);
        }
        if(map.containsKey(tkeys().isValid())){
            txr.setValid(map.getBoolean(tkeys().isValid()));
        }
        if(map.containsKey(tkeys().scopes()) && map.get(tkeys().scopes()) != null){
            txr.setScopes(JSONArray.fromObject(map.getString(tkeys().scopes())));
        }

       return txr;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        if(value.getParentID() != null) {
            data.put(tkeys().parentID(), value.getParentID().toString());
        }
        data.put(tkeys().issuedAt(), value.getIssuedAt());
        data.put(tkeys().lifetime(), value.getLifetime());
        data.put(tkeys().expiresAt(), value.getExpiresAt());
        data.put(tkeys().isValid(), value.isValid());
        data.put(tkeys().tokenType(), value.getTokenType());
        if(value.hasScopes()){
            data.put(tkeys().scopes(), value.getScopes().toString());
        }
        if(value.hasAudience()){
            data.put(tkeys().audience(), value.getAudience());
        }
        if(value.hasResources()){
            data.put(tkeys().resource(), value.getResource().toString());
        }
        if(!StringUtils.isTrivial(value.getIssuer())){
            data.put(tkeys().issuer(), value.getIssuer());
        }
    }
}
