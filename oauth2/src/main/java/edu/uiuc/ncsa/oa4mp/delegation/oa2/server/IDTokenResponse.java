package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.JWTUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.*;

/**
 * This is the superclass for responses that must include the ID token.
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/17 at  1:03 PM
 */
public abstract class IDTokenResponse extends IResponse2 {
    public IDTokenResponse(AccessTokenImpl accessToken,
                           RefreshTokenImpl refreshToken,
                           boolean isOIDC) {
        super(isOIDC);
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    AccessToken accessToken;
    RefreshTokenImpl refreshToken;

    public boolean hasRefreshToken() {
        return refreshToken != null;
    }

    public RefreshTokenImpl getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshTokenImpl refreshToken) {
        this.refreshToken = refreshToken;
    }

    ServiceTransaction serviceTransaction;

    public ServiceTransaction getServiceTransaction() {
        return serviceTransaction;
    }

    public void setServiceTransaction(ServiceTransaction serviceTransaction) {
        this.serviceTransaction = serviceTransaction;
    }

    public JSONWebKey getJsonWebKey() {
        return jsonWebKey;
    }

    public void setJsonWebKey(JSONWebKey jsonWebKey) {
        this.jsonWebKey = jsonWebKey;
    }

    JSONWebKey jsonWebKey;

    public boolean isSignToken() {
        return signToken;
    }

    public void setSignToken(boolean signToken) {
        this.signToken = signToken;
    }

    boolean signToken = false;

    JSONObject claims;

    public JSONObject getClaims() {
        if (claims == null) {
            claims = new JSONObject();
        }
        return claims;
    }

    public void setClaims(JSONObject claims) {
        this.claims = claims;
    }

    /**
     * The server must decide which scopes to return if any.
     *
     * @return
     */
    public Collection<String> getSupportedScopes() {
        return supportedScopes;
    }

    public void setSupportedScopes(Collection<String> supportedScopes) {
        this.supportedScopes = supportedScopes;
    }

    Collection<String> supportedScopes = new ArrayList<>();

    /**
     * Write JSON response to response's output stream
     *
     * @param response Response to write to
     */
    public void write(HttpServletResponse response) throws IOException {
        DebugUtil.trace(this, "starting ID token response write");
        // m contains the top-level JSON object that is serialized for the response. The
        // claims are part of this and keyed to the id_token.
        HashMap m = new HashMap();
        if (accessToken.getToken().contains("?")) { // low budget JWT test
            m.put(ACCESS_TOKEN, accessToken.encodeToken()); // it is not a JWT, encode it
        } else {
            m.put(ACCESS_TOKEN, accessToken.getToken());  // its a JWT, don't encode it
        }
        m.put(EXPIRES_IN, (accessToken.getLifetime() / 1000));

        m.put(TOKEN_TYPE, "Bearer");
        if (getRefreshToken() != null && getRefreshToken().getToken() != null) {
            if (getRefreshToken().getToken().contains("?")) { // low budget JWT test
                m.put(REFRESH_TOKEN, getRefreshToken().encodeToken());
            } else {
                m.put(REFRESH_TOKEN, getRefreshToken().getToken()); // don't encode JWTs
            }
            // CIL-1655
            m.put("refresh_token_" + EXPIRES_IN, refreshToken.getLifetime()/1000);
            m.put("refresh_token_" + OA2Claims.ISSUED_AT, refreshToken.getIssuedAt()/1000);
        }
        if (!getSupportedScopes().isEmpty()) {
            // construct the scope response.
            String ss = "";
            boolean firstPass = true;
            for (String s : getSupportedScopes()) {
                ss = ss + (firstPass ? "" : " ") + s;
                if (firstPass) {
                    firstPass = false;
                }
            }
            m.put(SCOPE, ss);
        }

        if (isOIDC()) {
            JSONObject claims = getClaims();
            try {
                String idTokken = null;
                if (isSignToken()) {
                    idTokken = JWTUtil.createJWT(claims, getJsonWebKey());
                } else {
                    idTokken = JWTUtil.createJWT(claims);
                }
                m.put(ID_TOKEN, idTokken);
            } catch (Throwable e) {
                throw new IllegalStateException("Error: cannot create ID token", e);
            }

        }

        JSONObject json = JSONObject.fromObject(m);
        DebugUtil.trace(this, "writing ID token response");

        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        Writer osw = response.getWriter();
        json.write(osw);
        osw.flush();
        osw.close();
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "{" +
                "accessToken=" + accessToken +
                ", refreshToken=" + refreshToken +
                ", signToken=" + signToken +
                ", claims=" + claims +
                ", supportedScopes=" + supportedScopes +
                '}';
    }
}
