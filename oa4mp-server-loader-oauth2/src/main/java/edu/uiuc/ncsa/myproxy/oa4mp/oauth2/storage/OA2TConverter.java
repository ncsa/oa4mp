package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.TransactionConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.sf.json.JSONArray;
import net.sf.json.JSONSerializer;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/12/14 at  1:35 PM
 */
public class OA2TConverter<V extends OA2ServiceTransaction> extends TransactionConverter<V> {
    public OA2TConverter(OA2TransactionKeys keys, IdentifiableProvider<V> identifiableProvider, TokenForge tokenForge, ClientStore<? extends Client> cs) {
        super(keys, identifiableProvider, tokenForge, cs);
    }

    protected OA2TransactionKeys getTCK() {
        return (OA2TransactionKeys) keys;
    }

    protected OA2TokenForge getTF2() {
        return (OA2TokenForge) getTokenForge();
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V st = super.fromMap(map, v);
        Object refreshToken = map.get(getTCK().refreshToken());

        if (refreshToken != null) {
            if (refreshToken instanceof RefreshToken) {
                st.setRefreshToken((RefreshToken) refreshToken);
            } else {
                st.setRefreshToken(getTF2().getRefreshToken(refreshToken.toString()));
            }
        }
        st.setRefreshTokenValid(map.getBoolean(getTCK().refreshTokenValid()));
        st.setRefreshTokenLifetime(map.getLong(getTCK().expiresIn()));
        st.setCallback(map.getURI(getTCK().callbackUri()));
        st.setNonce(map.getString(getTCK().nonce()));
        if (map.get(getTCK().scopes()) != null) {
            net.sf.json.JSONArray json = (net.sf.json.JSONArray) JSONSerializer.toJSON(map.get(getTCK().scopes()));
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(json);
            st.setScopes(zzz);
        }
        if(map.get(getTCK().authTime()) != null){
            st.setAuthTime(map.getDate(getTCK().authTime));
        }
        return st;
    }

    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
        super.toMap(t, map);
        if (t.getRefreshToken() != null) {
            map.put(getTCK().refreshToken(), t.getRefreshToken().getToken());
        }
        map.put(getTCK().refreshTokenValid(), t.isRefreshTokenValid());
        if (t.getCallback() != null) {
            map.put(getTCK().callbackUri(), t.getCallback().toString());
        }
        map.put(getTCK().expiresIn(), t.getRefreshTokenLifetime());
        if (t.getNonce() != null && 0 < t.getNonce().length()) {
            map.put(getTCK().nonce(), t.getNonce());
        }
        if (t.getScopes().isEmpty()) {
            return;
        }
        JSONArray jsonArray = new JSONArray();
        for (String s : t.getScopes()) {
            jsonArray.add(s);
        }
        map.put(getTCK().scopes(), jsonArray.toString());
        if(t.hasAuthTime()){
            map.put(getTCK().authTime(), t.getAuthTime());
        }
    }

}
