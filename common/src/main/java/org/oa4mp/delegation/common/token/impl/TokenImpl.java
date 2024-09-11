package org.oa4mp.delegation.common.token.impl;

import org.oa4mp.delegation.common.token.NewToken;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.configuration.XProperties;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.Date;
import java.util.Map;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkNoNulls;
import static edu.uiuc.ncsa.security.core.util.Identifiers.*;

/**
 * OAuth 1.0 tokens always have an associated shared secret. These do not.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 16, 2011 at  12:58:52 PM
 */
public class TokenImpl implements NewToken {

    public static final String TOKEN_TYPE = "token_type";
    public static final String EXPIRES_AT = "expires_at";
    public static final String IS_JWT = "is_jwt";
    public static final String PAYLOAD = "payload";
    public static final String TOKEN = "token";
    public static final String JTI = "jti";

    public TokenImpl() {
    }

    XProperties params = new XProperties();
    String version = null;

    @Override
    public String getVersion() {
        if (version == null) {
            if (params.containsKey(VERSION_2_0_TAG)) {
                version = params.getString(VERSION_2_0_TAG);
            }else{
                version = params.getString(VERSION_2_0_TAG);
            }
        }
        return version;
    }

    /**
     * If this is a JWT, then this returns the JTI. If not, it just returns the token.
     *
     * @return
     */
    public URI getJti() {
        return jti;
    }

    public void setJti(URI jti) {
        this.jti = jti;
        init(jti);
    }

    URI jti;

    /**
     * Convenience method to return the JTI as an identifier.
     *
     * @return
     */
    public Identifier getJTIAsIdentifier() {
        return BasicIdentifier.newID(getJti());
    }

    /**
     * Checks if the version is null, effectively meaning it was created before versions existed.
     *
     * @return
     */
    public boolean isOldVersion() {
        return getVersion() == null || getVersion().equals(VERSION_1_0_TAG);
    }

    public boolean isJWT() {
        return isJWT;
    }

    public void setJWT(boolean JWT) {
        isJWT = JWT;
    }

    boolean isJWT = false;

    public TokenImpl(String sciToken, URI jti) {
        this.token = sciToken;
        this.jti = jti;
        isJWT = true; // only place we can determine this
        init(jti);
    }


    public TokenImpl(URI token) {
        if (token == null) {
            return; // can happen. Return so there is not an NPE.
        }
        this.token = token.toString();
        this.jti = token;
        init(token);
    }

    protected void init(URI uri) {
        if (uri == null) {
            return; // can happen. Return so there is not an NPE.
        }
        String s = uri.getQuery();
        if (StringUtils.isTrivial(uri.getQuery())) {
            // Version 1.0 tokens.
            version = VERSION_1_0_TAG;

        } else {
            // Version 2.0+ tokens.
            Map<String, String> parameters = getParameters(uri);
            params.putAll(parameters);
            version = VERSION_2_0_TAG;
        }

    }

    String token = null;

    public String getToken() {
        return token;
    }

    public URI getURIToken() {
        return URI.create(token);
    }

    public void setToken(URI token) {
        this.token = token.toString();
    }

    public void setToken(String token) {
        this.token = token;
    }

    public boolean equals(Object obj) {
        // special case: If the object is null and the values are, then accept them as being equal.
        if (!(obj instanceof TokenImpl)) return false;
        TokenImpl at = (TokenImpl) obj;
        // special case is that this has null values and the object is null.
        // These then should be considered equal.
        if (!checkNoNulls(getURIToken(), at.getURIToken())) return false;
        if (!checkNoNulls(getVersion(), at.getVersion())) return false;
        if (!at.getToken().equals(getToken())) return false;
        if (at.getLifetime() != getLifetime()) return false;
        if (at.getIssuedAt() != getIssuedAt()) return false;
        return true;
    }

    /**
     * Does everything but final ]. Over-ride this and your {@link #toString()} will work
     *
     * @return
     */
    protected StringBuilder createString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(getClass().getSimpleName() + "[");
        stringBuilder.append(JTI + "=" + getJti());
        if (isJWT) {
            if (getToken() == null) {
                stringBuilder.append(", token=(null)");
            } else {
                stringBuilder.append(", token=" + getToken());
            }
        }
        if (params == null || params.isEmpty()) {
            stringBuilder.append(", " + TIMESTAMP_TAG + "=" + getIssuedAt());
            stringBuilder.append(", " + LIFETIME_TAG + "=" + getLifetime());
            stringBuilder.append(", " + VERSION_TAG + "=" + getVersion());

        } else {
            for (Object x : params.keySet()) {
                String key = (String) x;
                stringBuilder.append(", " + key + "=" + params.getString(key));
            }
        }
        return stringBuilder;

    }

    @Override
    public String toString() {
        return createString().toString() + "]";
    }


    @Override
    public boolean isExpired() {
        if (DebugUtil.isEnabled()) {
            Date expireTS = new Date();
            expireTS.setTime(getLifetime() + getIssuedAt());
        }
        if (getLifetime() + getIssuedAt() < System.currentTimeMillis()) {
            return true;
        }
        return false;
    }


    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    long lifetime = -1L;

    @Override
    public long getLifetime() {
        if (lifetime < 0) {
            if (params.containsKey(LIFETIME_TAG)) {
                lifetime = params.getLong(LIFETIME_TAG);
            }
        }
        return lifetime;
    }

    long issuedAt = -1L;

    public void setVersion(String version) {
        this.version = version;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    @Override
    public long getIssuedAt() {
        if (issuedAt < 0) {
            if (params.containsKey(TIMESTAMP_TAG)) {
                issuedAt = params.getLong(TIMESTAMP_TAG);
            }
        }
        return issuedAt;
    }

    @Override
    public JSONObject toJSON() {
        return newToJSON();
    }
    /*
     public static final String TOKEN_TYPE_TAG = "type";
    public static final String TIMESTAMP_TAG = "ts";
    public static final String VERSION_TAG = "version";
    public static final String LIFETIME_TAG = "lifetime";
     */
    protected JSONObject newToJSON() {
        JSONObject json = new JSONObject();
        json.put(TIMESTAMP_TAG, getIssuedAt());
        json.put(LIFETIME_TAG, getLifetime());
        json.put(VERSION_TAG, getVersion());
        json.put(TOKEN_TYPE, getTokenType());
        json.put(EXPIRES_AT, getExpiresAt());
        json.put(IS_JWT, isJWT());
        if(hasPayload()){
            json.put(PAYLOAD, getPayload());
        }
        json.put(TOKEN, getToken());
        json.put(JTI, getJti().toString());
        return json;
    }

    protected JSONObject oldToJSON() {
        JSONObject json = new JSONObject();
        json.put(TIMESTAMP_TAG, getIssuedAt());
        json.put(LIFETIME_TAG, getLifetime());
        if (isJWT) {
            json.put("jwt", token.toString());
        }
        json.put(TOKEN, getJti().toString());
        return json;
    }

    public boolean hasPayload() {
        return payload != null;
    }

    /**
     * If this token is a JWT, the is the actual payload.
     *
     * @return
     */
    public JSONObject getPayload() {
        return payload;
    }

    public void setPayload(JSONObject payload) {
        this.payload = payload;
    }

    JSONObject payload = null;

    @Override
    public void fromJSON(JSONObject json) {
        if(json.containsKey(TOKEN_TYPE)){
            if(!json.getString(TOKEN_TYPE).equals(getTokenType())){
                throw new IllegalArgumentException("wrong token type. Expected \"" + getTokenType() + "\", but got \"" + json.getString(TOKEN_TYPE) + "\".");
            }
             newFromJSON(json);;
        } else{
            oldFromJSON(json);
        }
    }
    protected String getTokenType(){
        return "token_impl";
    }
    public void oldFromJSON(JSONObject json) {
        if (!json.containsKey(TOKEN)) {
            throw new IllegalArgumentException("the json object is not a token");
        }
        jti = URI.create(json.getString(TOKEN));
        if (json.containsKey("jwt")) {
            token = json.getString("jwt");
            isJWT = true;
        } else {
            token = jti.toString();
            isJWT = false;
        }
        if (json.containsKey(TIMESTAMP_TAG)) {
            issuedAt = json.getLong(TIMESTAMP_TAG);
        }
        if (json.containsKey(LIFETIME_TAG)) {
            lifetime = json.getLong(LIFETIME_TAG);
        }
    }

    protected void newFromJSON(JSONObject json) {
        jti = URI.create(json.getString(JTI));
        if(json.containsKey(PAYLOAD)){
            setPayload(json.getJSONObject(PAYLOAD));
        }
        setExpiresAt(json.getLong(EXPIRES_AT));
        setLifetime(json.getLong(LIFETIME_TAG));
        setVersion(json.getString(VERSION_TAG));
        setIssuedAt(json.getLong(TIMESTAMP_TAG));
        setJWT(json.getBoolean(IS_JWT));
        setToken(json.getString(TOKEN));
        setJti(URI.create(json.getString(JTI)));
    }

    public String encodeToken() {
        return TokenUtils.b32EncodeToken(this);
    }

    public void decodeToken(String b32Encoded) {
        String rawToken = TokenUtils.b32DecodeToken(b32Encoded);
        URI newToken = URI.create(rawToken);
        setToken(rawToken);
        init(newToken);
    }

    public static void main(String[] args) {
        String token = "https://dev.cilogon.org/oauth2/5b8c19145ec68a66c32eeedd228faf12?type=accessToken&ts=1652301290756&version=v2.0&lifetime=900000";
        token = token + "&eid=" + "898611f963df7c8bf48351a7350813adee417e57";
        TokenImpl token1 = new TokenImpl(URI.create(token));
        System.out.println(token1);
    }

    public long getExpiresAt() {
        if (expiresAt < 0L) {
            expiresAt = getIssuedAt() + getLifetime();
        }
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    long expiresAt = -1L;
}
