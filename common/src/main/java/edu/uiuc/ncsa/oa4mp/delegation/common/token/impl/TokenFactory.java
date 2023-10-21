package edu.uiuc.ncsa.oa4mp.delegation.common.token.impl;

import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/19/23 at  1:08 PM
 */
public class TokenFactory {
    /**
     * Used by the {@link #parseRawToken(String, TokenImpl)} function. If you get any token as a string,
     * create an instance with the raw token (unparsed) and this will figure out what the token
     * is and populate it.
     */
    public static class TokenParse{
        public TokenParse(String rawToken, TokenImpl token) {
            this.rawToken = rawToken;
            this.token = token;
        }

        String rawToken;
        TokenImpl token;
        URI jti;
        boolean isJWT = false;
    }

    /**
     * Parses the raw string from, e.g., a server response and populates a token from that.
     * <h2>NOTE</h2>
     * This does <it>no</it> validation on the raw token if it is a JWT, since many times
     * that is not needed and it would create a lot of overhead for no reason. If you need
     * the JWT validated, do it separately.
     *
     * @param rawToken
     * @param token
     */
   protected static void parseRawToken(String rawToken, TokenImpl token){
       if(TokenUtils.isBase32(rawToken)){
           String decodedToken = TokenUtils.b32DecodeToken(rawToken);
           token.setToken(rawToken);
           token.setJti(URI.create(decodedToken));
           token.setJWT(false);
           return;
       }
       // next thing to try is to see if it's a JWT
       StringTokenizer st = new StringTokenizer(rawToken, ".");
       if(1 < st.countTokens() && st.countTokens() <= 3){
           st.nextToken();
           String payload = st.nextToken();
           try {
               byte[] x = Base64.decodeBase64(payload);
               String pp = new String(x, StandardCharsets.UTF_8);
               JSONObject jsonObject = JSONObject.fromObject(pp);
               token.setPayload(jsonObject);
               // remember that in JWTs the times are in seconds.
               if(jsonObject.containsKey("jti")){
                   token.setJti(URI.create(jsonObject.getString("jti")));
               }
               if(jsonObject.containsKey("iat")){
                   token.setIssuedAt(1000*jsonObject.getLong("iat"));
               }
               if(jsonObject.containsKey("exp")){
                   long expiresAt = jsonObject.getLong("exp");
                   token.setExpiresAt(1000*expiresAt);
                   token.setLifetime(1000*expiresAt - token.getIssuedAt());
               }
               token.setJWT(true);
               token.setToken(rawToken);// can't really change this. Should be a string...
               return;
           }catch(Throwable t){
               // so it ain't a JWT.
               t.printStackTrace();
           }
       }
       // so at this point, we have to assume that it is indeed just a token.
       token.setJWT(false);
       token.setJti(URI.create(rawToken));
       token.setToken(rawToken);
   }
   public static RefreshTokenImpl createRT(String rawToken){
        RefreshTokenImpl refreshToken = new RefreshTokenImpl();
        parseRawToken(rawToken, refreshToken);
        return refreshToken;
   }

    /**
     * Recreate the object from its serialized form.
     * @param json
     * @return
     */
    public static RefreshTokenImpl createRT(JSONObject json){
       RefreshTokenImpl refreshToken = new RefreshTokenImpl(URI.create("a"));
       refreshToken.fromJSON(json);
       return refreshToken;
    }
    public static AccessTokenImpl createAT(String rawToken) {
        AccessTokenImpl accessToken = new AccessTokenImpl();
        parseRawToken(rawToken, accessToken);
        return accessToken;
    }

    /**
     * Recreate the object from it serialized format. This will fail if the object is not
     * serialized propertly!
     * @param json
     * @return
     */
    public static AccessTokenImpl createAT(JSONObject json){
       AccessTokenImpl accessToken = new AccessTokenImpl(URI.create("a"));
       accessToken.fromJSON(json);
       return accessToken;
    }
    public static IDTokenImpl createIDT(String rawToken){
        IDTokenImpl idToken = new IDTokenImpl();
        parseRawToken(rawToken, idToken);
        return idToken;
    }


    /**
     * In some (legacy) cases, all you have is a parsed payload. This method
     * will create a partial token for this, missing the raw token. Not great but
     * about the best that can be done since the original token and its signature, header,
     * etc. are missing is fake. Alternately, if the argument is just a serialized ID
     * token, this will deserialize it and return it.
     * @param json
     * @return
     */
    public static IDTokenImpl createIDT(JSONObject json){
        if(json.containsKey("token_type")){
            // This is actually a serialized ID token. Deserialize it.
            IDTokenImpl idToken = new IDTokenImpl(URI.create("a"));
            if(!json.getString("token_type").equals(idToken.getTokenType())){
                throw new IllegalArgumentException("Attempt to deserialize a non ID token, type is \"" + json.getString("token_type") + "\".");
            }
            idToken.fromJSON(json);
            return idToken;
        }
        if(!json.containsKey("jti")){
            throw new IllegalArgumentException("unknown token type");
        }
         IDTokenImpl idToken = new IDTokenImpl(URI.create(json.getString("jti")));
         idToken.setExpiresAt(1000*json.getLong("exp"));
         idToken.setPayload(json);
         idToken.setIssuedAt(1000*json.getLong("iat"));
         idToken.setLifetime(idToken.getExpiresAt() - idToken.getIssuedAt());
         idToken.setToken("A." + Base64.encodeBase64URLSafeString(json.toString().getBytes(StandardCharsets.UTF_8)) + ".Z");
         idToken.setJWT(true); // since all ID tokens are JWTs!
         return idToken;
    }

}
