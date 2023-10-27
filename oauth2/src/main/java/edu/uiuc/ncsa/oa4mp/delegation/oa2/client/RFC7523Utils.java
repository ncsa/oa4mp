package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.NonceHerder;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.MyOtherJWTUtil2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7523Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

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
     * Does a POST to the endpoint using the client's key.
     *
     * @param serviceClient
     * @param oa2Client
     * @param accessTokenEndpoint
     * @param parameters
     * @return
     */
    public static String doPost(ServiceClient serviceClient,
                                Client oa2Client,
                                URI accessTokenEndpoint,
                                String keyID,
                                Map parameters) {
        try {

            Map<String, Object> map = new HashMap<>();
            // Scopes require a bit of surgery. It is possible they are sent as an
            // unparsed string, but should be turned into a JSON array of strings.
            if(parameters.containsKey(OA2Constants.SCOPE)){
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
                map.put(OA2Constants.SCOPE, array);
            }
            map.putAll(parameters);
            JSONWebKey key = findKey(oa2Client, keyID);
            if (key == null) {
                throw new IllegalStateException("Client \"" + oa2Client.getIdentifierString() + "\" key not found.");
            }
            JSONObject request = createBasicJWT(oa2Client);
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

            request.put(OA2Claims.AUDIENCE, accessTokenEndpoint.toString()); // token endpoint.
            String payload = MyOtherJWTUtil2.createJWT(request, key);
            map.put(CILENT_ASSERTION, payload);
            map.put(CILENT_ASSERTION_TYPE, ASSERTION_JWT_BEARER);
            return serviceClient.doPost(map);
        } catch (Throwable t) {
          /*  if (DebugUtil.isEnabled()) {
                t.printStackTrace();
            }*/
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new GeneralException("POST error for client \"" + oa2Client.getIdentifierString() + "\"", t);
        }

    }


    /**
     * Every basic JWT has the same structure. Create it here.
     *
     * @param client
     * @return
     */
    protected static JSONObject createBasicJWT(Client client) {
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

    protected static JSONWebKey findKey(Client client, String kid) {
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
     * Creates an authorization grant for the client. Note that clients must have a previous
     * trust relationship to do this, or it will fail.
     *
     * @param serviceClient
     * @param client
     * @param parameters
     */
    public static String doTokenRequest(ServiceClient serviceClient,
                                      Client client,
                                      URI tokenEndpoint,
                                      String kid,
                                      Map parameters) {
        JSONObject authGrant = createBasicJWT(client);
        authGrant.putAll(parameters); // this sets the contents of the authorization grant.
        JSONWebKey key = findKey(client, kid);
        if (key == null) {
            throw new IllegalStateException("Client \"" + client.getIdentifierString() + "\" key not found.");
        }

        // This will be sent to the post method and is used to construct that
        JSONObject request = createBasicJWT(client);
        request.putAll(parameters);
        request.put(OA2Constants.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        try {
            request.put(ASSERTION, MyOtherJWTUtil2.createJWT(authGrant, key));
        } catch (Throwable t) {
            if (DebugUtil.isEnabled()) {
                t.printStackTrace();
            }
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            }
            throw new GeneralException("Token request error for client \"" + client.getIdentifierString() + "\"", t);
        }
        return doPost(serviceClient, client, tokenEndpoint, kid, request);
    }
}
