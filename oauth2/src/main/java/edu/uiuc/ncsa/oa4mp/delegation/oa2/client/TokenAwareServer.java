package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.BasicRequest;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.IDTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.JWTUtil;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.*;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.*;

/**
 * Since the processing of claims is to be supported for refresh tokens as well, the machinery for it should be
 * available generally to access and refresh token servers.
 * <p>Created by Jeff Gaynor<br>
 * on 9/13/17 at  2:37 PM
 */
public abstract class TokenAwareServer extends ASImpl {
    /**
     * Is OIDC enabled for the server?
     */
    boolean serverOIDCEnabled = true; // Server can issue ID tokens

    boolean clientOIDCEnabled = false; // client can request ID tokens

    ServiceClient serviceClient;
    URI issuer;
    URI getIssuer(){
        return issuer;
    }


    public ServiceClient getServiceClient() {
        return serviceClient;
    }


    public TokenAwareServer(ServiceClient serviceClient,
                            URI issuer,
                            String wellKnown,
                            boolean serverOIDCEnabled
                            ) {
        super(serviceClient.host());
        this.serviceClient = serviceClient;
        this.wellKnown = wellKnown;
        this.serverOIDCEnabled = serverOIDCEnabled;
        this.tokenEndpoint = serviceClient.host();
        this.issuer = issuer;
    }

    String wellKnown = null;


    public JSONWebKeys getJsonWebKeys() {
        // Fix for OAUTH-164, id_token support follows.
        if (wellKnown == null) {
            throw new NFWException("no well-known URI has been configured. Please add this to the configuration file.");
        }
        return JWTUtil.getJsonWebKeys(getServiceClient(), wellKnown);
    }

    protected JSONObject getAndCheckResponse(String response) {
        // It is now ok to have empty responses as long as the status code was 200.
        // If it gets to here, the status has been checked. 
        if (response == null || response.length() == 0) {
            return new JSONObject();
        }
        if (response.startsWith("<") || response.startsWith("\n")) {
            // this is actually HTML
            //    System.out.println(getClass().getSimpleName() + ".getAccessToken: response from server is " + response);
            throw new GeneralException("response from server was html: " + response);
        }
        JSONObject jsonObject = null;
        try {
            jsonObject = JSONObject.fromObject(response);
        } catch (Throwable t) {
            // it is at this point we may not have a JSON object because the request failed and the server returned an
            // error string. Throw an exception, print the response.
            DebugUtil.trace(this, "Response from server was not a JSON Object: " + response);
            throw new GeneralException("the server encountered an error and the response was not JSON:\n\"" + response + "\"", t);
        }
        if (!jsonObject.getString(TOKEN_TYPE).equals(BEARER_TOKEN_TYPE)) {
            throw new GeneralException("incorrect token type");
        }
        return jsonObject;
    }

    /**
     * Takes the response JSON object that contains the ID token and the
     * request and checks that it is a valid ID Token for this client.
     * Result is the actual ID token (also a JSON Object).
     * @param jsonObject
     * @param atRequest
     * @return
     */
    protected IDTokenImpl getAndCheckIDToken(JSONObject jsonObject, BasicRequest atRequest) {
        if (!serverOIDCEnabled) {
            return null;
        }
        JSONWebKeys keys = getJsonWebKeys();

        JSONObject claims;
        if (!jsonObject.containsKey(ID_TOKEN)) {
            throw new GeneralException("ID Token not found.");
        }
        claims = JWTUtil.verifyAndReadJWT(jsonObject.getString(ID_TOKEN), keys);
        if (claims.isNullObject()) {
            // the response may be a null object. At this point it means that there was a null
            // object and that the resulting signature was valid for it, so that is indeed the server response.
            return null;
        }
        // Now we have to check claims.
        if(!claims.containsKey(AUDIENCE)){
            throw new GeneralException(" ID Token missing " + AUDIENCE + " claim for \"" + atRequest.getClient().getIdentifierString() + "\"");
        }
        if (!claims.getString(AUDIENCE).equals(atRequest.getClient().getIdentifierString())) {
            throw new GeneralException(" ID Token audience is incorrect. Expected \"" + claims.getString(AUDIENCE) + "\", got \"" + atRequest.getClient().getIdentifierString() + "\"");
        }

        if(!claims.containsKey(ISSUER)){
            throw new GeneralException(" ID Token missing " + ISSUER + " claim for \"" + atRequest.getClient().getIdentifierString() + "\"");
        }

        try {
            URL host = getAddress().toURL();

            URL remoteHost = new URL(claims.getString(ISSUER));
            if(!remoteHost.equals(getIssuer().toURL())){
                // ok something is off -- port specified? pick it a part a bit more, but
                // don't sweat it too much
                if (!host.getProtocol().equals(remoteHost.getProtocol()) ||
                        !host.getHost().equals(remoteHost.getHost()) ||
                        !remoteHost.equals(getIssuer().toURL()) ||
                        host.getPort() != remoteHost.getPort()) {
                    throw new GeneralException(" ID Token issuer is incorrect. Got \"" + remoteHost + "\", expected \"" + host + "\"");
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        if (!claims.containsKey(EXPIRATION)) {
            throw new GeneralException(" ID Token claims failed to have required expiration");
        }
        long exp = Long.parseLong(claims.getString(EXPIRATION)) * 1000L; // convert to ms.
        if (exp <= System.currentTimeMillis()) {
            throw new GeneralException(" ID Token expired claims.");
        }
        return TokenFactory.createIDT(jsonObject.getString(ID_TOKEN));
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(URI tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    URI tokenEndpoint;
}
