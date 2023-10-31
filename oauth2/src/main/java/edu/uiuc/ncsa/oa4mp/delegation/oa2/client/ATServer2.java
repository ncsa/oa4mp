package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.ATResponse;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.ATServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.IDTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8628Constants;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.*;


/**
 * This class handles the client call to the access token endpoint
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:33 PM
 */

public class ATServer2 extends TokenAwareServer implements ATServer {
    /**
     * Placeholder class for storing ID tokens. ID tokens are consumable in the sense that once we
     * get them back, they are checked for validity and passed along to the client. The problem is that
     * many applications (such as Kubernetes) are using them as a "poor man's SciToken", necessitating
     * that we keep them around for at least a bit. This store holds the raw token (as a string) and
     * the corresponding {@link net.sf.json.JSONObject} keyed by {@link edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken}.
     */

    public static class IDTokenEntry {
        public JSONObject idToken;
        public String rawToken;

        @Override
        public String toString() {
            return this.getClass().getSimpleName() + "[idToken=" + (idToken == null ? "(null)" : idToken.toString(2)) + ", rawToken=" + (rawToken == null ? "(null)" : rawToken) + "]";
        }
    }


    static HashMap<URI, IDTokenImpl> idTokenStore = new HashMap<>();

    public static HashMap<URI, IDTokenImpl> getIDTokenStore() {
        return idTokenStore;
    }

    public ATServer2(ServiceClient serviceClient,
                     String wellKnown,
                     boolean oidcEnabled,
                     long expiresIn,
                     boolean useBasicAuth) {
        super(serviceClient, wellKnown, oidcEnabled);
        this.useBasicAuth = useBasicAuth;
    }

    boolean useBasicAuth = false;

    /**
     * Processes access token request
     *
     * @param atRequest Access token request
     * @return Access token response
     */
    public ATResponse processATRequest(ATRequest atRequest) {
        return getAccessToken(atRequest);
    }


    /**
     * Gets access token. This also returns the refresh token (if any) in the response.
     * Note that there are claims that are returned in the a parameter map for the
     * "subject" and the "issued at" claims. Neither of these require any processing
     * here, but clients should have them available to enforce policies.
     * The id token is returned as a parameter in the response as well as a json object.
     *
     * @param atRequest Access token request
     * @return Access token response
     */
    protected ATResponse2 getAccessToken(ATRequest atRequest) {
        HashMap m = new HashMap();
        Map params = atRequest.getParameters();
        if (atRequest.getParameters() != null) {
            m.putAll(params);
        }
        if (atRequest.isRfc8628()) {
            DebugUtil.trace(this, "rfc 8628 case, use http header for token? " + useBasicAuth);
            m.put(RFC8628Constants.DEVICE_CODE, atRequest.getAuthorizationGrant().getToken());
            m.put(GRANT_TYPE, RFC8628Constants.GRANT_TYPE_DEVICE_CODE);
            m.put(CLIENT_ID, atRequest.getClient().getIdentifierString());
        } else {
            if (params.get(REDIRECT_URI) == null) {
                throw new GeneralException("Error: the client redirect uri was not set in the request.");
            }
            DebugUtil.trace(this, "getting access token, use http header for token? " + useBasicAuth);
            // Create the request
            m.put(AUTHORIZATION_CODE, atRequest.getAuthorizationGrant().getToken());
            m.put(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
            m.put(REDIRECT_URI, params.get(REDIRECT_URI));
        }


        String response = null;
        if (atRequest.getClient().hasJWKS()) {
            response = RFC7523Utils.doPost(getServiceClient(),
                    atRequest.getClient(),
                    getTokenEndpoint(),
                    atRequest.getKeyID(),
                    m);
        } else {
            String clientID = atRequest.getClient().getIdentifierString();
            String clientSecret = atRequest.getClient().getSecret();

            if (useBasicAuth) {
                response = getServiceClient().doGet(m, clientID, clientSecret);
            } else {
                m.put(CLIENT_ID, clientID);
                m.put(CLIENT_SECRET, clientSecret);
                response = getServiceClient().doGet(m);
            }
        }
        JSONObject jsonObject = getAndCheckResponse(response);
        if (!jsonObject.containsKey(ACCESS_TOKEN)) {
            throw new IllegalArgumentException("Error: No access token found in server response");
        }
        AccessTokenImpl at = TokenFactory.createAT(jsonObject.getString(ACCESS_TOKEN));
        if(jsonObject.containsKey(EXPIRES_IN)) {
            at.setExpiresAt(jsonObject.getLong(EXPIRES_IN) * 1000); // This is authoritative
        }
        //AccessTokenImpl at = new AccessTokenImpl(URI.create(jsonObject.getString(ACCESS_TOKEN)));
        RefreshTokenImpl rt = null;
        if (jsonObject.containsKey(REFRESH_TOKEN)) {
            // the refresh token is optional, so if it is missing then there is nothing to do.
            //rt = new RefreshTokenImpl(URI.create(jsonObject.getString(REFRESH_TOKEN)));
            rt = TokenFactory.createRT(jsonObject.getString(REFRESH_TOKEN));
            if(jsonObject.containsKey("refresh_token_lifetime")){
                rt.setLifetime(jsonObject.getLong("refresh_token_lifetime")*1000);
                rt.setIssuedAt(jsonObject.getLong("refresh_token_iat")*1000);
                rt.setExpiresAt(rt.getIssuedAt() + rt.getLifetime());
            }
        }
        ServletDebugUtil.trace(this, "Is OIDC enabled? " + serverOIDCEnabled);
        IDTokenImpl idToken = null;
        if(jsonObject.containsKey(ID_TOKEN)){
               idToken = TokenFactory.createIDT(jsonObject.getString(ID_TOKEN));
               getIDTokenStore().put(at.getJti(), idToken);
        }
        if (serverOIDCEnabled && idToken!=null) {

            // and now the specific checks for ID tokens returned by the AT server.
            // It is possible (e.g. RFC 8628) that there is no nonce or that the client is not configured to
            // send one, so only check if there was one in the request to start with.
            if (m.containsKey(NONCE) && !idToken.getPayload().getString(NONCE).equals(atRequest.getParameters().get(NONCE))) {
                throw new GeneralException("Error: Incorrect nonce \"" + atRequest.getParameters().get(NONCE) + "\" returned from server");
            }

        } else {
            ServletDebugUtil.trace(this, "Skipping id token entry...");
        }
        ATResponse2 atr = createResponse(at, rt, idToken);
        atr.setParameters(params);
        return atr;
    }

    protected ATResponse2 createResponse(AccessTokenImpl at, RefreshTokenImpl rt, IDTokenImpl idToken) {
        return new ATResponse2(at, rt, idToken);
    }

}
