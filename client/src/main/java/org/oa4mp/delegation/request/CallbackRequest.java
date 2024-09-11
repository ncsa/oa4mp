package org.oa4mp.delegation.request;

import org.oa4mp.delegation.server.CBServer;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.Verifier;

import javax.servlet.ServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 12, 2011 at  1:04:34 PM
 */
public class CallbackRequest extends BasicRequest {
    public ServletRequest getServletRequest() {
        return servletRequest;
    }

    public void setServletRequest(ServletRequest servletRequest) {
        this.servletRequest = servletRequest;
    }

    ServletRequest servletRequest;

    public CallbackRequest(ServletRequest servletRequest) {
        super();
        setServletRequest(servletRequest);
    }

    AuthorizationGrant authorizationGrant;
    Verifier verifier;

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    public Verifier getVerifier() {
        return verifier;
    }

    public void setVerifier(Verifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public Response process(Server server) {
        if (server instanceof CBServer) {
            return ((CBServer) server).processCallback(this);
        }
        return super.process(server);
    }

    @Override
    public String toString() {
        String out = getClass().getSimpleName() + "[";
        out = out + "grant=" + (authorizationGrant == null?"(null)":authorizationGrant);
        out = out + ", verifier=" + (verifier==null?"(null)":verifier);
        out = out + "]";
        return out;
    }
}
