package edu.uiuc.ncsa.oa4mp.delegation.server.request;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.ProtectedAsset;

import javax.servlet.http.HttpServletRequest;

/**
 * Request for a {@link ProtectedAsset}
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  12:32:22 PM
 */
public class PARequest extends IssuerRequest {
    @Override
    public int getType() {
        return PA_TYPE;
    }

    public PARequest(HttpServletRequest servletRequest, ServiceTransaction transaction) {
        super(servletRequest, transaction);
    }

    AccessToken accessToken;

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public Response process(Server server) {
        if (server instanceof PAIssuer) {
            return ((PAIssuer) server).processProtectedAsset(this);
        }
        return super.process(server);
    }
}
