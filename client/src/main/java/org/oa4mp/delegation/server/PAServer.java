package org.oa4mp.delegation.server;

import org.oa4mp.delegation.request.PARequest;
import org.oa4mp.delegation.request.PAResponse;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * A server tasked with processing requests for a protected asset.
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  10:46 AM
 */
public interface PAServer extends DoubleDispatchServer {
    public PAResponse processPARequest(PARequest request);

}
