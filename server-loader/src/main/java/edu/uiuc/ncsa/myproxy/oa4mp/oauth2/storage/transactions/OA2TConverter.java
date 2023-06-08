package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.TransactionConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.net.URI;
import java.util.Collection;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

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

        if (refreshToken == null) {
            st.setRefreshToken(null);
        }else{
            if (refreshToken instanceof RefreshToken) {
                st.setRefreshToken((RefreshToken) refreshToken);
            } else {
                RefreshTokenImpl rt = new RefreshTokenImpl(URI.create(refreshToken.toString()));
                st.setRefreshToken(rt);
            }
        }
        Object rawAG = map.get(getTCK().authGrant());
        if (rawAG == null) {
            if (st.getIdentifier() != null) {
                AuthorizationGrantImpl ag = new AuthorizationGrantImpl(st.getIdentifier().getUri());
                st.setAuthorizationGrant(ag);
            }
        } else {
            if (rawAG instanceof AuthorizationGrant) {
                st.setAuthorizationGrant((AuthorizationGrant) rawAG);
            } else {
                AuthorizationGrantImpl ag = new AuthorizationGrantImpl(URI.create(rawAG.toString()));
                st.setAuthorizationGrant(ag);
            }
        }
        if(map.containsKey(getTCK().atJWT())){
            st.setATJWT(map.getString(getTCK().atJWT()));
        }
        if(map.containsKey(getTCK().rtJWT())){
            st.setRTJWT(map.getString(getTCK().rtJWT()));
        }

        st.setUserCode(map.getString(getTCK().userCode()));
        st.setRFC8628Request(map.getBoolean(getTCK().isRFC8628()));
        st.setProxyId(map.getString(getTCK().proxyID()));
        st.setAuthGrantLifetime(map.getLong(getTCK().authzGrantLifetime()));
        st.setRefreshTokenValid(map.getBoolean(getTCK().refreshTokenValid()));
        st.setRefreshTokenLifetime(map.getLong(getTCK().refreshTokenLifetime()));
        st.setAccessTokenLifetime(map.getLong(getTCK().expiresIn()));
        st.setCallback(map.getURI(getTCK().callbackUri()));
        st.setNonce(map.getString(getTCK().nonce()));
        st.setRequestState(map.getString(getTCK().reqState()));
        // https://github.com/rcauth-eu/OA4MP/commit/9dc129a679d7d701fdbba7173363e4aa82adcd2a
        if(map.get(getTCK().validatedScopes())!=null){
            JSONArray json = (JSONArray) JSONSerializer.toJSON(map.get(getTCK().validatedScopes()));
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(json);
            st.setValidatedScopes(zzz);
        }
        if (map.get(getTCK().scopes()) != null) {
            JSONArray json = (JSONArray) JSONSerializer.toJSON(map.get(getTCK().scopes()));
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(json);
            st.setScopes(zzz);
        }
        if (map.get(getTCK().authTime()) != null) {
            st.setAuthTime(map.getDate(getTCK().authTime));
        }
        if (map.get(getTCK().states()) != null) {
            st.setState((JSONObject) JSONSerializer.toJSON(map.get(getTCK().states())));
        } else {
            st.setState(new JSONObject());
        }
        /*
        Must recover any state from user-created/modified access or refresh tokens.
         */
        if (st.hasAccessToken()) {
            AccessTokenImpl accessToken = (AccessTokenImpl) st.getAccessToken();
            JSONObject atData = st.getATData();
            if (atData != null && !atData.isEmpty()) {
                if (atData.containsKey(OA2Claims.ISSUED_AT)) {
                    accessToken.setIssuedAt(1000 * atData.getLong(OA2Claims.ISSUED_AT));
                    if (atData.containsKey(OA2Claims.EXPIRATION)) {
                        accessToken.setLifetime(1000 * (atData.getLong(OA2Claims.EXPIRATION) - atData.getLong(OA2Claims.ISSUED_AT)));
                    }
                }
            }
        }
        if (st.hasRefreshToken()) {
            RefreshTokenImpl rt = (RefreshTokenImpl) st.getRefreshToken();
            JSONObject rtData = st.getRTData();
            if (rtData != null && !rtData.isEmpty()) {
                if (rtData.containsKey(OA2Claims.ISSUED_AT)) {
                    rt.setIssuedAt(1000 * rtData.getLong(OA2Claims.ISSUED_AT));
                    if (rtData.containsKey(OA2Claims.EXPIRATION)) {
                        rt.setLifetime(1000 * (rtData.getLong(OA2Claims.EXPIRATION) - rtData.getLong(OA2Claims.ISSUED_AT)));
                    }
                }

            }
        }
        return st;
    }

    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
        super.toMap(t, map);
        if (t.getRefreshToken() != null) {
            map.put(getTCK().refreshToken(), t.getRefreshToken().getJti().toString());
        }
        if (t.getAuthorizationGrant() == null) {
            // If the transaction is old, this will be missing. Create it from the
            // identifier
            AuthorizationGrantImpl ag = new AuthorizationGrantImpl(t.getIdentifier().getUri());
            map.put(getTCK().authGrant(), ag);
        } else {
            map.put(getTCK().authGrant(), t.getAuthorizationGrant().getToken());
        }
        map.put(getTCK().refreshTokenValid(), t.isRefreshTokenValid());
        if (t.getCallback() != null) {
            map.put(getTCK().callbackUri(), t.getCallback().toString());
        }
        if(!StringUtils.isTrivial(t.getATJWT())){
            map.put(getTCK().atJWT(), t.getATJWT());
        }
        if(!StringUtils.isTrivial(t.getRTJWT())){
            map.put(getTCK().rtJWT(), t.getRTJWT());
        }

        map.put(getTCK().authzGrantLifetime(), t.getAuthzGrantLifetime());
        map.put(getTCK().expiresIn(), t.getAccessTokenLifetime());
        map.put(getTCK().refreshTokenLifetime(), t.getRefreshTokenLifetime());
        map.put(getTCK().isRFC8628(), t.isRFC8628Request());
        if(!isTrivial(t.getProxyId())){
            map.put(getTCK().proxyID(), t.getProxyId());
        }
        if (!isTrivial(t.getUserCode())) {
            map.put(getTCK().userCode(), t.getUserCode());
        }
        if(!t.getValidatedScopes().isEmpty()){
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(t.getValidatedScopes());
            map.put(getTCK().validatedScopes(), jsonArray.toString());
        }
        if (!isTrivial(t.getNonce())) {
            map.put(getTCK().nonce(), t.getNonce());
        }
        if(!isTrivial(t.getRequestState())){
            map.put(getTCK().reqState(), t.getRequestState());
        }
        JSONArray jsonArray = new JSONArray();
        // OK, so in some weird cases the content of the scopes can be a thing called a MorphDynaBean in the JSON
        // library. This is a known issue that sometimes it returns these, so we have to do a test and convert
        // or we can get a very unhelpful class cast exception. This is really bizarre since the type of
        // the scopes is a Collection<String>, so the fact that it can contain DynaBeans at all is become of some
        /// weirdness with erasure in the JSON library that they should not be doing.
        for (Object s : t.getScopes()) {
            if (DebugUtil.isEnabled()) {
                if (!(s instanceof String)) {
                    DebugUtil.trace(this, "Erasure error. A String was expected, but an object of class " + s.getClass().getCanonicalName() + " was found instead.");
                    DebugUtil.trace(this, "Value of the class=\"" + s + "\"");
                }
            }
            jsonArray.add(s.toString());
        }
        map.put(getTCK().scopes(), jsonArray.toString());
        if (t.hasAuthTime()) {
            map.put(getTCK().authTime(), t.getAuthTime());
        }
        map.put(getTCK().states(), t.getState().toString());
    }

}
