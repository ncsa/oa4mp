package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerRequest;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.token.AccessToken;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/14 at  11:32 AM
 */
public class RTIRequest extends IssuerRequest {
    @Override
    public int getType() {
        return RT_TYPE;
    }

    boolean isOIDC = true;
    public RTIRequest(ServiceTransaction transaction, boolean isOIDC) {
        super(transaction);
        this.isOIDC =isOIDC;
    }

    public RTIRequest(HttpServletRequest servletRequest, ServiceTransaction transaction, boolean isOIDC) {
        super(servletRequest, transaction);
        this.isOIDC = isOIDC;
    }

    public RTIRequest(HttpServletRequest servletRequest, ServiceTransaction transaction, AccessToken accessToken, boolean isOIDC) {
        super(servletRequest, transaction);
        this.accessToken = accessToken;
        this.isOIDC = isOIDC;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    AccessToken accessToken;

    @Override
    public Response process(Server server) {
        if(server instanceof RTI2){
            return ((RTI2)server).processRTRequest(this, isOIDC);
        }
        return super.process(server);
    }
}
