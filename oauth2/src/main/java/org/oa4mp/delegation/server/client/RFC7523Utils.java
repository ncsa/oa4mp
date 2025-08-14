package org.oa4mp.delegation.server.client;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.server.NonceHerder;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;
import org.oa4mp.delegation.server.server.RFC7523Constants;
import org.oa4mp.delegation.server.server.claims.OA2Claims;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/5/23 at  10:02 AM
 */
public class RFC7523Utils implements RFC7523Constants {
    /**
     * Does a POST to the endpoint using the client's key. This fulfills RFC 7523's section 2.2,
     * authentication using a JWT. This returns a string (a JSON object) since there are
     * various checks that can/should
     * be done on the response, but not necessarily immediately. I.e. this sets the {@link RFC7523Constants#CLIENT_ASSERTION}
     * and POSTS to the token endpoint.
     *
     * @param serviceClient -  the service client
     * @param baseClient - the client making the call.
     * @param accessTokenEndpoint -- the token endpoint for the service client
     * @param keyID - the id of the baseClient's keys to use for signing
     * @param parameters - additional parameters
     * @return
     */
    public static String doPost(ServiceClient serviceClient,
                                BaseClient baseClient,
                                URI accessTokenEndpoint,
                                String keyID,
                                Map parameters) {
        return doPost(serviceClient,
                baseClient,
                accessTokenEndpoint,
                findKey(baseClient, keyID),
                parameters);
    }

    /**
     * This creates the authorization request
     * See {@link #doPost(ServiceClient, BaseClient, URI, String, Map)}
     * @param serviceClient
     * @param baseClient
     * @param accessTokenEndpoint
     * @param key
     * @param parameters
     * @return
     */

    public static String doPost(ServiceClient serviceClient,
                                BaseClient baseClient,
                                URI accessTokenEndpoint,
                                JSONWebKey key,
                                Map parameters) {

        try {

            Map<String, Object> map = new HashMap<>();
            // Scopes require a bit of surgery. It is possible they are sent as an
            // unparsed string, but should be turned into a JSON array of strings.
/*            if(parameters.containsKey(OA2Constants.SCOPE)){
                setupScopes(parameters);
            }*/
            map.putAll(parameters);
            if (key == null) {
                throw new IllegalStateException("Client \"" + baseClient.getIdentifierString() + "\" key not found.");
            }
            JSONObject authNRequest = createBasicJWT(baseClient);
        /*
        From the OIDC spec., section 9:


        iss
            REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
        sub
            REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
        aud
            REQUIRED. Audience. The aud (audience) Claim. Value that identifies the Authorization Server as an intended audience.
                                The Authorization Server MUST verify that it is an intended audience for the token.
                                The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
        jti
            REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token.
                             These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties;
                             any such negotiation is beyond the scope of this specification.
        exp
            REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
        iat
            OPTIONAL. Time at which the JWT was issued.


         */

            authNRequest.put(OA2Claims.AUDIENCE, accessTokenEndpoint.toString()); // token endpoint.
            String payload = MyOtherJWTUtil2.createJWT(authNRequest, key);
            map.put(CLIENT_ASSERTION, payload);
            map.put(CLIENT_ASSERTION_TYPE, ASSERTION_JWT_BEARER);
            return serviceClient.doPost(map);
        } catch (Throwable t) {
          /*  if (DebugUtil.isEnabled()) {
                t.printStackTrace();
            }*/
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new GeneralException("POST error for client \"" + baseClient.getIdentifierString() + "\"", t);
        }
    }


    /**
     * Every basic JWT for the assertion and client_assertion (i.e., auth grant and authorization)
     * has the same structure. Create it here.
     *
     * @param client
     * @return
     */
    protected static JSONObject createBasicJWT(BaseClient client) {
        JSONObject json = new JSONObject();
        String clientid = client.getIdentifierString();

        json.put(OA2Claims.ISSUER, clientid);
        json.put(OA2Claims.SUBJECT, clientid);
        json.put(OA2Claims.JWT_ID, clientid + (clientid.endsWith("/") ? "" : "/") + "rfc7523/" + NonceHerder.createNonce());
        // All times are in seconds, so divide by 1000
        json.put(OA2Claims.EXPIRATION, (System.currentTimeMillis() + DEFAULT_LIFETIME)/1000);// 15 minutes lifetime
        json.put(OA2Claims.ISSUED_AT, System.currentTimeMillis()/1000);
        return json;
    }

    /**
     * Finds the key for signing from the given client using the given key id (kid).
     * @param client
     * @param kid
     * @throws IllegalStateException if no such key
     * @return
     */
    protected static JSONWebKey findKey(BaseClient client, String kid) {
        if (!client.hasJWKS()) {
            throw new IllegalStateException("Client \"" + client.getIdentifierString() + "\" is missing JSON Web Keys.");
        }
        JSONWebKeys jwks = client.getJWKS();
        JSONWebKey key = null;
        if (jwks.size() == 1) {
            key = jwks.getDefault();
        } else {
            if (StringUtils.isTrivial(kid)) {
                throw new IllegalStateException("client \"" + client.getIdentifierString() + "\" has multiple keys, but no key id (kid). Cannot encode token.");
            }
            key = jwks.get(kid);
        }
        return key;
    }

    /**
     * Creates an authorization grant for the client as per RFC 7523 section 2.1, and the authorization (section 2.2) .
     * Note that clients must have a previous
     * trust relationship to do this, or it will fail.
     *
     * @param serviceClient
     * @param client
     * @param parameters
     */
    public static String doTokenRequest(ServiceClient serviceClient,
                                      BaseClient client,
                                      URI tokenEndpoint,
                                      String kid,
                                      Map parameters) {
        JSONObject authGrant = createBasicJWT(client);
        if(parameters.containsKey(OA2Constants.SCOPE)){
            setupScopes(parameters);
        }
        authGrant.putAll(parameters); // this sets the contents of the authorization grant.
        JSONWebKey key = findKey(client, kid);
        if (key == null) {
            throw new IllegalStateException("Client \"" + client.getIdentifierString() + "\" key not found.");
        }

        // This will be sent to the post method and is used to construct that
        JSONObject tokenRequest = createBasicJWT(client);
        tokenRequest.putAll(parameters);
        tokenRequest.put(OA2Constants.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        try {
            tokenRequest.put(ASSERTION, MyOtherJWTUtil2.createJWT(authGrant, key));
        } catch (Throwable t) {
            if (DebugUtil.isEnabled()) {
                t.printStackTrace();
            }
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new GeneralException("Token request error for client \"" + client.getIdentifierString() + "\"", t);
        }
        return doPost(serviceClient, client, tokenEndpoint, kid, tokenRequest);
    }

    /**
     * Do the token request via the admin client, using one of it's key for signing. Note that everything here
     * is as a {@link BaseClient} because of Java package visibility issues. You have to keep straight
     * which is which.
     * @param serviceClient
     * @param adminClient
     * @param client
     * @param tokenEndpoint
     * @param adminKey
     * @param parameters
     * @return
     */
    public static String doInitFlowTokenRequest(ServiceClient serviceClient,
                                                BaseClient adminClient,
                                                JSONWebKey adminKey,
                                                BaseClient client,
                                                URI tokenEndpoint,
                                                Map parameters) {
        if (adminKey == null) {
            throw new IllegalStateException("Client \"" + client.getIdentifierString() + "\" key not found.");
        }

        // This will be sent to the post method and is used to construct that
        JSONObject tokenRequest = createBasicJWT(client); // 2.1
        // Scopes require a bit of surgery. It is possible they are sent as an
        // unparsed string, but should be turned into a JSON array of strings.
        if(parameters.containsKey(OA2Constants.SCOPE)){
            setupScopes(parameters);
        }
        tokenRequest.putAll(parameters);
        tokenRequest.put(OA2Constants.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        try {
            tokenRequest.put(ASSERTION, MyOtherJWTUtil2.createJWT(tokenRequest)); // unsigned if admin client is starting flow
        } catch (Throwable t) {
            if (DebugUtil.isEnabled()) {
                t.printStackTrace();
            }
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new GeneralException("Token request error for client \"" + client.getIdentifierString() + "\"", t);
        }
        return doPost(serviceClient, adminClient, tokenEndpoint, adminKey, tokenRequest);
    }

    private static void setupScopes(Map parameters) {
        Object obj = parameters.get(OA2Constants.SCOPE);
        parameters.remove(OA2Constants.SCOPE);
        JSONArray array;
        if(obj instanceof JSONArray){
            array = (JSONArray) obj;
        }
        else{
            if(obj instanceof String){
                array = new JSONArray();
                StringTokenizer stringTokenizer = new StringTokenizer((String)obj, " ");
                while(stringTokenizer.hasMoreTokens()){
                    array.add(stringTokenizer.nextToken());
                }
            }else{
                throw new IllegalArgumentException("unknown scope type of " + obj.getClass() + ": \"" + obj + "\"");
            }
        }
        parameters.put(OA2Constants.SCOPE, array);
    }
}
