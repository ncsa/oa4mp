package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
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
        accessToken = new AccessTokenImpl(map.getURI(keys.accessToken()));
        atValid = map.getBoolean(keys.accessTokenValid());
        rtValid = map.getBoolean(keys.refreshTokenValid());
        atLifetime = map.getLong(keys.expiresIn());
        rtLifetime = map.getLong(keys.refreshTokenLifetime());
        refreshToken = new RefreshTokenImpl(map.getURI(keys.refreshToken()));
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
        tokens.put(OA2Constants.ACCESS_TOKEN,  accessToken.toJSON());
        tokens.put(OA2Constants.REFRESH_TOKEN,  refreshToken.toJSON());
        return tokens;
    }
}
