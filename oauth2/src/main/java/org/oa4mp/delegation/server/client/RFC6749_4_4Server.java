package org.oa4mp.delegation.server.client;

import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.client.request.RFC6749_4_4Request;
import org.oa4mp.delegation.client.request.RFC6749_4_4_Response;
import org.oa4mp.delegation.server.OA2Constants;

import java.net.URI;
import java.util.Map;

public class RFC6749_4_4Server extends TokenAwareServer {
    public RFC6749_4_4Server(ServiceClient serviceClient, URI issuer, String wellKnown, boolean serverOIDCEnabled) {
        super(serviceClient, issuer, wellKnown, serverOIDCEnabled);
    }

    public RFC6749_4_4_Response processRFC6749_4_4Request(RFC6749_4_4Request request) {
        Map parameters = request.getParameters();
        String rawResponse = null;
        RFC6749_4_4_Response response = new RFC6749_4_4_Response();
        if (parameters.containsKey(OA2Constants.CLIENT_ID)) {
            rawResponse = getServiceClient().doPost(parameters,
                    (String) parameters.get(OA2Constants.CLIENT_ID),
                    (String) parameters.get(OA2Constants.CLIENT_SECRET));
        }
        if (request.hasKeyID()) {
            rawResponse = RFC7523Utils.doPost(getServiceClient(), request.getClient(), getTokenEndpoint(), request.getKeyID(), parameters);
        }
        if (rawResponse != null) {
            JSONObject jsonObject = JSONObject.fromObject(rawResponse);
            response.setParameters(jsonObject);
        }
        // Note that the spec is very explicit that a refresh token is never returned
        // in the initial exchange.
        return response;
    }

}
