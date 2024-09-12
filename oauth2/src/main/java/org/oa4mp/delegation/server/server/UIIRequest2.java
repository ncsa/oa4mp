package org.oa4mp.delegation.server.server;


import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.request.IssuerRequest;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AccessToken;

import javax.servlet.http.HttpServletRequest;

/**
 * Request to issuer for UserInfo.
 * <p>Created by Jeff Gaynor<br>
 * on 10/7/13 at  2:36 PM
 */
public class UIIRequest2 extends IssuerRequest {
    @Override
    public int getType() {
        return UI_TYPE;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    String username;
    public UIIRequest2(HttpServletRequest servletRequest, ServiceTransaction transaction, AccessToken accessToken) {
        super(servletRequest, transaction);
        this.accessToken = accessToken;
    }

    public UIIRequest2(HttpServletRequest servletRequest, AccessToken accessToken) {
          super(servletRequest, null);
          this.accessToken = accessToken;
      }
    private AccessToken accessToken;

    @Override
     public Response process(Server server) {
         if (server instanceof UII2) {
             return ((UII2) server).processUIRequest(this);
         }
         return super.process(server);
     }

    /**
     * Getter for access token
     * @return Access token
     */
    public AccessToken getAccessToken() {
        return accessToken;
    }

    /**
     * Setter for access token
     * @param accessToken  Access token
     */
    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }
}
