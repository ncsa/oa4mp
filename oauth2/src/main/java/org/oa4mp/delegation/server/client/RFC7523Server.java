package org.oa4mp.delegation.server.client;

import org.oa4mp.delegation.request.RFC7523Request;
import org.oa4mp.delegation.request.RFC7523Response;
import org.oa4mp.delegation.server.server.RFC7523Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONObject;

import java.net.URI;

import static org.oa4mp.delegation.server.OA2Constants.ID_TOKEN;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/6/23 at  3:11 PM
 */
public class RFC7523Server extends TokenAwareServer implements RFC7523Constants {
    public RFC7523Server(ServiceClient serviceClient, URI issuer, String wellKnown, boolean oidcEnabled) {
        super(serviceClient, issuer, wellKnown, oidcEnabled);
    }

    public RFC7523Response processRFC7523Request(RFC7523Request request) {
        String response = RFC7523Utils.doTokenRequest(getServiceClient(),
                request.getClient(),
                getTokenEndpoint(),
                request.getKeyID(),
                request.getParameters());

        RFC7523Response rfc7523Response = new RFC7523Response();
        rfc7523Response.setResponse(JSONObject.fromObject(response)); // contains access token and refresh token.

        // This checks the ID token and verifies it. Use this, not the raw ID token in the response.
        // Not all clients return them, e.g. pure OAuth 2 clients.
        if(rfc7523Response.getResponse().containsKey(ID_TOKEN)) {
            rfc7523Response.setIdToken(getAndCheckIDToken(rfc7523Response.getResponse(), request));
        }
        return rfc7523Response;
    }
}
