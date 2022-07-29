package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.client.server.PAServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  3:38:19 PM
 */
public class PARequest extends BasicRequest {
    public Response process(Server server) {
        if (server instanceof PAServer) {
            return ((PAServer) server).processPARequest(this);
        }
        return super.process(server);
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    AccessToken accessToken;
}
