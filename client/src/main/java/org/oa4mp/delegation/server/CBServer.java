package org.oa4mp.delegation.server;

import org.oa4mp.delegation.request.CallbackRequest;
import org.oa4mp.delegation.request.CallbackResponse;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * Models a server that handles the callback, if there is one.
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  11:02 AM
 */
public interface CBServer extends DoubleDispatchServer {
    public CallbackResponse processCallback(CallbackRequest callbackRequest);
}
