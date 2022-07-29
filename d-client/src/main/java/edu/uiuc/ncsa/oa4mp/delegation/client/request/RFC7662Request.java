package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.client.server.ATServer;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.RFC7662Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;

/**
 * Note that since this uses bearer tokens, the access token must always be supplied.
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  6:15 AM
 */
public class RFC7662Request extends BasicRequest{
    public Response process(Server server) {
        if (server instanceof ATServer) {
            return ((RFC7662Server) server).processRFC7662Request(this);
        }
        return super.process(server);
    }
    public boolean hasAccessToken(){
        return accessToken != null;
    }
    public boolean hasRefreshToken(){
        return refreshToken != null;
    }
    AccessTokenImpl accessToken;
    RefreshTokenImpl refreshToken;

    public AccessTokenImpl getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessTokenImpl accessToken) {
        this.accessToken = accessToken;
    }

    public RefreshTokenImpl getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshTokenImpl refreshToken) {
        this.refreshToken = refreshToken;
    }
 }
