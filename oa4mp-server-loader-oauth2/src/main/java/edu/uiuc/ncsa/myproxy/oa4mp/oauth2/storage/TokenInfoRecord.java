package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import net.sf.json.JSONObject;

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
        rtValid = map.getBoolean(keys.refreshTokenValid());
        atLifetime = map.getLong(keys.expiresIn());
        rtLifetime = map.getLong(keys.refreshTokenLifetime());
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
        tokens.put(OA2Constants.ACCESS_TOKEN,  formatToken(accessToken, atLifetime,  atValid));
        tokens.put(OA2Constants.REFRESH_TOKEN,  formatToken(refreshToken, rtLifetime, rtValid));
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
}
