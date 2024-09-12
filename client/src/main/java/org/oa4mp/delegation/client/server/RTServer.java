package org.oa4mp.delegation.client.server;

import org.oa4mp.delegation.client.request.RTRequest;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;
import org.oa4mp.delegation.common.services.Response;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/14 at  11:20 AM
 */
public interface  RTServer extends DoubleDispatchServer {
    public abstract Response processRTRequest (RTRequest rtRequest) ;
}
