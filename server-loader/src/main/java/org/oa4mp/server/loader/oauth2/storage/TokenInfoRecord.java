package org.oa4mp.server.loader.oauth2.storage;

import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2TransactionKeys;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.security.core.Identifier;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenUtils;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.server.RFC8693Constants;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import net.sf.json.JSONObject;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/16/22 at  10:38 AM
 */
public class TokenInfoRecord {
    Identifier clientID;
    Identifier transactionID;
    AccessTokenImpl accessToken;
    long atLifetime = 0L;
    boolean atValid = false;
    RefreshTokenImpl refreshToken;
    boolean rtValid = false;
    long rtLifetime = 0L;

    /**
     * For use in SQL stores
     * @param map
     * @param keys
     */
    public void fromMap(ColumnMap map, OA2TransactionKeys keys) {
        clientID = map.getIdentifier(keys.clientKey());
        transactionID = map.getIdentifier(keys.identifier());
        if(map.containsKey(keys.atJWT()) && null!= map.get(keys.atJWT())){
             // So it's a JWT
            accessToken = new AccessTokenImpl(map.getString(keys.atJWT()),map.getURI(keys.accessToken()));
        }else {
            accessToken = new AccessTokenImpl(map.getURI(keys.accessToken()));
        }
        atValid = map.getBoolean(keys.accessTokenValid());
        atLifetime = map.getLong(keys.expiresIn());
        rtLifetime = map.getLong(keys.refreshTokenLifetime());
        rtValid = map.getBoolean(keys.refreshTokenValid());
        if(map.containsKey(keys.rtJWT()) && null!=map.get(keys.rtJWT())) {
            // Its a JWT
            refreshToken = new RefreshTokenImpl(map.getString(keys.rtJWT()),map.getURI(keys.refreshToken()));
        }else{
            refreshToken = new RefreshTokenImpl(map.getURI(keys.refreshToken()));
        }
    }

    /**
     * For use in stores like memory or file
     * @param t
     */
    public void fromTransaction(OA2ServiceTransaction t){
        if(t == null){
            return; // nixx to do
        }
        if(t.getClient()!=null) {
            clientID = t.getOA2Client().getIdentifier();
        }
        transactionID=t.getIdentifier();
        if(t.getAccessToken() != null){
            accessToken = (AccessTokenImpl) t.getAccessToken();
            atLifetime = t.getAccessTokenLifetime();
            atValid = t.isAccessTokenValid();
        }
        if(t.getRefreshToken()!= null){
            refreshToken = (RefreshTokenImpl) t.getRefreshToken();
            rtLifetime = t.getRefreshTokenLifetime();
            rtValid = t.isRefreshTokenValid();
        }
    }

    public JSONObject toJSON(){
        JSONObject tokens = new JSONObject();
        if(accessToken!=null && accessToken.getJti()!=null) {
            tokens.put(OA2Constants.ACCESS_TOKEN, formatToken(accessToken, atLifetime, atValid));
        }
        if(refreshToken != null && refreshToken.getJti()!=null) {
            tokens.put(OA2Constants.REFRESH_TOKEN, formatToken(refreshToken, rtLifetime, rtValid));
        }
        return tokens;
    }
    protected JSONObject formatToken(TokenImpl token, long lifetime,boolean isValid){
        JSONObject json = new JSONObject();
        json.put(OA2Claims.JWT_ID, token.getJti().toString());
        if(token.isJWT()){
            json.put("token" , token.getToken());
        }else{
            json.put("token" , TokenUtils.b32EncodeToken(token));
        }
        json.put("lifetime", lifetime);
        json.put("issued_at" , token.getIssuedAt());
        json.put("is_valid",isValid);
        return json;
    }
    public boolean hasAccessToken(){
        return accessToken != null;
    }
    public boolean hasRefreshToken(){
        return refreshToken != null;
    }

    /**
     * This has either a refresh or an access token
     * @param txr
     */
    public void fromTXRecord(Identifier clientID, TXRecord txr){
        if(txr == null){
            return; // nixx to do
        }
        this.clientID = clientID;
        if(txr.getTokenType().equals(RFC8693Constants.ACCESS_TOKEN_TYPE)){
            if(txr.getStoredToken()==null){
                // its a JWT
                accessToken = new AccessTokenImpl(URI.create(txr.getIdentifierString()));
            }else{
                accessToken = new AccessTokenImpl(txr.getStoredToken(), URI.create(txr.getIdentifierString()));
            }
            atLifetime = accessToken.getLifetime();
            atValid = txr.isValid();
        }
        if(txr.getTokenType().equals(RFC8693Constants.REFRESH_TOKEN_TYPE)){
            if(txr.getStoredToken()==null){
                // its a JWT
                refreshToken = new RefreshTokenImpl(URI.create(txr.getIdentifierString()));
            }else{
                refreshToken = new RefreshTokenImpl(txr.getStoredToken(), URI.create(txr.getIdentifierString()));
            }
            rtLifetime = refreshToken.getLifetime();
            rtValid = txr.isValid();

        }

        transactionID= txr.getParentID();
    }

    @Override
    public boolean equals(Object obj) {
        if(!(obj instanceof TokenInfoRecord)){
            return false;
        }
        if(obj == null){
            return false;
        }
        TokenInfoRecord tir = (TokenInfoRecord) obj;
        if(hasAccessToken()){
            return accessToken.equals(tir.accessToken);
        }
        if(hasRefreshToken()){
            return refreshToken.equals(tir.refreshToken);
        }
        return false;
    }
}
