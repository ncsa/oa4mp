package edu.uiuc.ncsa.oa4mp.delegation.server.issuers;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.AGRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  3:34 PM
 */
public interface AGIssuer extends DoubleDispatchServer {
    public IssuerResponse processAGRequest(AGRequest authorizationGrantRequest);
}
