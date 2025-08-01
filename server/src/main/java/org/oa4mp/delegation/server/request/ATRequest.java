package org.oa4mp.delegation.server.request;

import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.issuers.ATIssuer;

import javax.servlet.http.HttpServletRequest;

/**
 * Request for a {@link AccessToken}.
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  12:30:35 PM
 */
public class ATRequest extends IssuerRequest {
    @Override
    public int getType() {
        return AT_TYPE;
    }

    public ATRequest(HttpServletRequest httpServletRequest, ServiceTransaction transaction) {
        super(httpServletRequest, transaction);
    }

    AuthorizationGrant authorizationGrant;

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
    }

    @Override
    public Response process(Server server) {
        if (server instanceof ATIssuer) {
            return ((ATIssuer) server).processATRequest(this);
        }
        return super.process(server);
    }


    public boolean isOidc() {
        return oidc;
    }

    public void setOidc(boolean oidc) {
        this.oidc = oidc;
    }

    boolean oidc = false;
}
