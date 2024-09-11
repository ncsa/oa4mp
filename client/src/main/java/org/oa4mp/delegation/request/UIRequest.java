package org.oa4mp.delegation.request;

import org.oa4mp.delegation.server.UIServer;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AccessToken;

/**
 * Created with IntelliJ IDEA.
 * User: wedwards
 * Date: 1/30/14
 * Time: 2:54 PM
 * To change this template use File | Settings | File Templates.
 */
public class UIRequest extends BasicRequest {
    public UIRequest(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    private AccessToken accessToken;

    public Response process(Server server) {
        if (server instanceof UIServer) {
           return ((UIServer) server).processUIRequest(this);
        }
        return super.process(server);
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }
}
