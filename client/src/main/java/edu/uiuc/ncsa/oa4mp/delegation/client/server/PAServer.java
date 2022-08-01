package edu.uiuc.ncsa.oa4mp.delegation.client.server;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.PARequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.PAResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * A server tasked with processing requests for a protected asset.
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  10:46 AM
 */
public interface PAServer extends DoubleDispatchServer {
    public PAResponse processPARequest(PARequest request);

}
