package org.oa4mp.delegation.server;

import org.oa4mp.delegation.request.AGRequest;
import org.oa4mp.delegation.request.AGResponse;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;

/**
 * Interface for servers tasked with issuing authorization grants.
 * <p>Created by Jeff Gaynor<br>
 * on 6/3/13 at  10:44 AM
 */
public interface AGServer extends DoubleDispatchServer {
    public AGResponse processAGRequest(AGRequest acRequest);

}
