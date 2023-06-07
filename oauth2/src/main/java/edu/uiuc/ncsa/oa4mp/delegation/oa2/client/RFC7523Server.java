package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.RFC7523Request;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.RFC7523Response;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7523Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/6/23 at  3:11 PM
 */
public class RFC7523Server extends TokenAwareServer implements RFC7523Constants {
    public RFC7523Server(ServiceClient serviceClient, String wellKnown, boolean oidcEnabled) {
        super(serviceClient, wellKnown, oidcEnabled);
    }

    public RFC7523Response processRFC7523Request(RFC7523Request request) {
        String response = RFC7523Utils.doPost(getServiceClient(), request.getClient(), getTokenEndpoint(), request.getParameters());

        RFC7523Response rfc7523Response = new RFC7523Response();
        rfc7523Response.setResponse(JSONObject.fromObject(response)); // contains access token and refresh token.
        // This checks the ID token and verifies it. Use this, not the raw ID token in the response.
        rfc7523Response.setIdToken(getAndCheckIDToken(rfc7523Response.getResponse(), request));
        return rfc7523Response;
    }
}
