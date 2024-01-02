package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.RFC7662Request;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.RFC7662Response;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.RFC7662Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7662Constants;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.HashMap;

/**
 * For RFC 7662 -- the introspection endpoint.
 * <p>Created by Jeff Gaynor<br>
 * on 5/18/21 at  6:02 PM
 */
public class RFC7662Server2 extends TokenAwareServer implements RFC7662Server, RFC7662Constants {
    public RFC7662Server2(ServiceClient serviceClient,
                          URI issuer,
                          String wellKnown,
                          boolean oidcEnabled) {
        super(serviceClient, issuer, wellKnown, oidcEnabled);
    }

    public RFC7662Response processRFC7662Request(RFC7662Request request) {
        HashMap<String, Object> parameters = new HashMap<>();
        String token;
        String out;
        Client client = request.getClient();

        if (request.hasAccessToken()) {
            // If there is an access token, use it as a bearer token.
            parameters.put(TOKEN_TYPE_HINT, TYPE_ACCESS_TOKEN);
            token = request.getAccessToken().getToken();
            parameters.put(TOKEN, token);
            out = getServiceClient().doPost(parameters, token);
        } else {
            parameters.put(TOKEN_TYPE_HINT, TYPE_REFRESH_TOKEN);
            token = request.getRefreshToken().getToken();
            parameters.put(TOKEN, token);
            // Have to use basic authorization if no bearer token.
            if(client.hasJWKS()){
                out = RFC7523Utils.doPost(getServiceClient(),
                        request.getClient(),
                        request.getTokenEndpoint(),
                        request.getKeyID(),
                        parameters);
            } else{
                out = getServiceClient().doPost(parameters, request.getClient().getIdentifierString(),request.getClient().getSecret());
            }
        }

        try {
            JSONObject jsonObject = JSONObject.fromObject(out);
            RFC7662Response response = new RFC7662Response();
            response.setResponse(jsonObject);
            return response;
        } catch (JSONException jsonException) {
            throw new GeneralException("Error parsing JSON from \"" + out + "\"");
        }
    }

}
