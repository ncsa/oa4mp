package org.oa4mp.delegation.client.request;

import org.oa4mp.delegation.client.server.AGServer;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  3:37:26 PM
 */
public class AGRequest extends BasicRequest {
    public Response process(Server server) {
        if (server instanceof AGServer) {
            return ((AGServer) server).processAGRequest(this);
        }
        return super.process(server);
    }
}
