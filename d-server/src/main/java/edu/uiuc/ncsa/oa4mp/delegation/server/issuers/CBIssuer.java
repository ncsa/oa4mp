package edu.uiuc.ncsa.oa4mp.delegation.server.issuers;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.CBRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.CBResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  3:35 PM
 */
public interface CBIssuer extends DoubleDispatchServer {
    public abstract CBResponse processCallbackRequest(CBRequest CBRequest);
}
