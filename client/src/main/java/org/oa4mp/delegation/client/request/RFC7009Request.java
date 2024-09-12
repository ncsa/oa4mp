package org.oa4mp.delegation.client.request;

import org.oa4mp.delegation.client.server.RFC7009Server;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  6:29 AM
 */
public class RFC7009Request extends RFC7662Request{
    @Override
    public Response process(Server server) {
         if (server instanceof RFC7009Server) {
             return ((RFC7009Server) server).processRFC7009Request(this);
         }
         return super.process(server);
     }
}
