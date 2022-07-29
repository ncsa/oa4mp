package edu.uiuc.ncsa.oa4mp.delegation.server.request;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;

import javax.servlet.http.HttpServletRequest;

/**
 * A request for an authorization grant.
 *
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  11:57:19 AM
 */
public class AGRequest extends IssuerRequest {
    public AGRequest(HttpServletRequest servletRequest, ServiceTransaction transaction) {
        super(servletRequest, transaction);
    }

    @Override
    public int getType() {
        return AG_TYPE;
    }

    @Override
    public Response process(Server server) {
        if (server instanceof AGIssuer) {
            return ((AGIssuer) server).processAGRequest(this);
        }
        return super.process(server);
    }
}
