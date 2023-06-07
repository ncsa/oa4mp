package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.RFC7009Request;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.RFC7009Response;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.RFC7009Server;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7662Constants;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;

import java.util.HashMap;

/**
 * For RFC 7009 -- the revocation endpoint.
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  6:31 AM
 */
public class RFC7009Server2 extends TokenAwareServer implements RFC7009Server, RFC7662Constants {
    public RFC7009Server2(ServiceClient serviceClient,
                          String wellKnown,
                          boolean oidcEnabled) {
        super(serviceClient, wellKnown, oidcEnabled);
    }

    @Override
    public RFC7009Response processRFC7009Request(RFC7009Request request) {
        HashMap<String, Object> parameters = new HashMap<>();
        if (request.hasRefreshToken()) {
            parameters.put(TOKEN_TYPE_HINT, TYPE_REFRESH_TOKEN);
            parameters.put(TOKEN, request.getRefreshToken().getToken());
        } else {
            parameters.put(TOKEN_TYPE_HINT, TYPE_ACCESS_TOKEN);
            parameters.put(TOKEN, request.getAccessToken().getToken());
        }
        // do post with access token as the bearer token.
        String out = getServiceClient().doPost(parameters, request.getAccessToken().getToken());
        // All that matters is that the server responds with a status of 200. Any content
        // is ignored.
        DebugUtil.trace(this, "got response \"" + out + "\" from server");
        RFC7009Response response = new RFC7009Response();
        return response;
    }
}
