package edu.uiuc.ncsa.oa4mp.delegation.client.server;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.CallbackRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.CallbackResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * Models a server that handles the callback, if there is one.
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  11:02 AM
 */
public interface CBServer extends DoubleDispatchServer {
    public CallbackResponse processCallback(CallbackRequest callbackRequest);
}
