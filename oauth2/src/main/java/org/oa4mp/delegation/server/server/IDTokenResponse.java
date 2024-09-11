package org.oa4mp.delegation.server.server;

import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.IDTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.TreeSet;

import static org.oa4mp.delegation.server.OA2Constants.*;

/**
 * This is the superclass for responses that must include the ID token.
 * Note that the ID token is in the {@link #getUserMetadata()}.
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

    public IDTokenImpl getIdToken() {
        return idToken;
    }

    public void setIdToken(IDTokenImpl idToken) {
        this.idToken = idToken;
    }

    IDTokenImpl idToken;

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

    JSONObject userMetadata;

    public JSONObject getUserMetadata() {
        if (userMetadata == null) {
            userMetadata = new JSONObject();
        }
        return userMetadata;
    }

    public void setUserMetadata(JSONObject userMetadata) {
        this.userMetadata = userMetadata;
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
            m.put("refresh_token_lifetime", refreshToken.getLifetime() / 1000);
            m.put("refresh_token_" + OA2Claims.ISSUED_AT, refreshToken.getIssuedAt() / 1000);
        }
        TreeSet<String> allScopes = new TreeSet<>();
        // Fix https://github.com/ncsa/oa4mp/issues/134
        OIDCServiceTransactionInterface st = (OIDCServiceTransactionInterface) getServiceTransaction();
        if (st.getATData().containsKey(SCOPE)) {
            allScopes.addAll(OA2Scopes.ScopeUtil.toScopes(st.getATData().getString(SCOPE)));
        }
        if (!getSupportedScopes().isEmpty()) {
            // construct the scope response.
            for (String s : getSupportedScopes()) {
                allScopes.add(s);
            }
        }

        String ss = OA2Scopes.ScopeUtil.toString(allScopes);
        if(!StringUtils.isTrivial(ss)) {
            m.put(SCOPE, ss);
        }
        // We have to compute the user metadata no matter what, but only return it if the
        // client is OIDC.
        if (isOIDC() || serviceTransaction.getResponseTypes().contains(RESPONSE_TYPE_ID_TOKEN)) {
            DebugUtil.trace(this, "writing ID token response");
            m.put(ID_TOKEN, getIdToken().getToken());
        }

        JSONObject json = JSONObject.fromObject(m);
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
                ", claims=" + userMetadata +
                ", supportedScopes=" + supportedScopes +
                '}';
    }
}
