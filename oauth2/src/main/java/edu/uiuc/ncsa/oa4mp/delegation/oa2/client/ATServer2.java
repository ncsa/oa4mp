package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.ATResponse;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.ATServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8628Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.*;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.ISSUED_AT;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.SUBJECT;


/**
 * This class handles the client call to the access token endpoint
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:33 PM
 */

public class ATServer2 extends TokenAwareServer implements ATServer {
    /**
     * Place holder class for storing ID tokens. ID tokens are consumable in the sense that once we
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


    static HashMap<String, IDTokenEntry> idTokenStore = new HashMap<String, IDTokenEntry>();

    public static HashMap<String, IDTokenEntry> getIDTokenStore() {
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
    long expiresIn = 0L;

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
            response = RFC7523Utils.doPost(getServiceClient(), atRequest.getClient(), getTokenEndpoint(), m);
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
        AccessTokenImpl at = new AccessTokenImpl(URI.create(jsonObject.getString(ACCESS_TOKEN)));
        RefreshTokenImpl rt = null;
        if (jsonObject.containsKey(REFRESH_TOKEN)) {
            // the refresh token is optional, so if it is missing then there is nothing to do.
            rt = new RefreshTokenImpl(URI.create(jsonObject.getString(REFRESH_TOKEN)));
        }
        ServletDebugUtil.trace(this, "Is OIDC enabled? " + oidcEnabled);

        if (oidcEnabled) {
            ServletDebugUtil.trace(this, "Processing id token entry");
            IDTokenEntry idTokenEntry = new IDTokenEntry();
            ServletDebugUtil.trace(this, "created new idTokenEntry ");
            JSONObject idToken = getAndCheckIDToken(jsonObject, atRequest);
            ServletDebugUtil.trace(this, "got id token = " + idToken.toString(2));
            if (jsonObject.containsKey(ID_TOKEN)) {
                params.put(RAW_ID_TOKEN, jsonObject.getString(ID_TOKEN));
                idTokenEntry.rawToken = (String) params.get(RAW_ID_TOKEN);
                ServletDebugUtil.trace(this, "raw token = " + idTokenEntry.rawToken);
            }

            idTokenEntry.idToken = idToken;
            ServletDebugUtil.trace(this, "idTokenEntry= " + idTokenEntry);

            // and now the specific checks for ID tokens returned by the AT server.
            // It is possible (e.g. RFC 8628) that there is no nonce or that the client is not configured to
            // send one, so only check if there was one in the request to start with.
            if (m.containsKey(NONCE) && !idToken.getString(NONCE).equals(atRequest.getParameters().get(NONCE))) {
                throw new GeneralException("Error: Incorrect nonce \"" + atRequest.getParameters().get(NONCE) + "\" returned from server");
            }

            params.put(ISSUED_AT, new Date(idToken.getLong(ISSUED_AT) * 1000L));
            params.put(SUBJECT, idToken.getString(SUBJECT));
            if (idToken.containsKey(AUTHORIZATION_TIME)) {
                // auth_time claim is optional (unless max_age is returned). At this point we do not do max_age.
                params.put(AUTHORIZATION_TIME, idToken.getLong(AUTHORIZATION_TIME));
            }
            params.put(ID_TOKEN, idToken);
            //params.put(EXPIRES_IN, expiresIn/1000 ); //convert to seconds.
            params.put(EXPIRES_IN, at.getLifetime() / 1000); // AT is definitive. Convert to seconds.
            ServletDebugUtil.trace(this, "Adding idTokenEntry with id = " + at.getToken() + " to the ID Token store. Store has " + getIDTokenStore().size() + " entries");
            getIDTokenStore().put(at.getToken(), idTokenEntry);
            ServletDebugUtil.trace(this, "ID Token store=" + getIDTokenStore().size());
            ServletDebugUtil.trace(this, "Added idTokenEntry to the ID Token store. Store now has " + getIDTokenStore().size() + " entries");
        } else {
            ServletDebugUtil.trace(this, "Skipping id token entry...");
        }
        ATResponse2 atr = createResponse(at, rt);
        atr.setParameters(params);
        return atr;
    }

    protected ATResponse2 createResponse(AccessTokenImpl at, RefreshTokenImpl rt) {
        return new ATResponse2(at, rt);
    }

}
