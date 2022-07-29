package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.client.server.RTServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/14 at  11:19 AM
 */
public class RTRequest extends BasicRequest {
    public RTRequest(Client client, Map<String, String> parameters) {
        super(client, parameters);
    }

    public RTRequest() {
    }

    public Response process(Server server) {
         if (server instanceof RTServer) {
             return ((RTServer) server).processRTRequest(this);
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

    RefreshToken refreshToken;

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }
}
