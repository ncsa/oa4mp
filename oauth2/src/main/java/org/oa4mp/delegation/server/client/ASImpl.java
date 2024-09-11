package org.oa4mp.delegation.server.client;


import org.oa4mp.delegation.common.services.AddressableServer;
import org.oa4mp.delegation.common.services.DoubleDispatchServer;
import org.oa4mp.delegation.common.services.Request;
import org.oa4mp.delegation.common.services.Response;

import java.net.URI;

/**
 * Addressable Server implementation to support double dispatch pattern(?)
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:31 PM
 */
public class ASImpl implements AddressableServer, DoubleDispatchServer {
    public ASImpl(URI address) {
        this.address = address;
    }

    URI address;
    public URI getAddress() {
        return address;
    }

    public Response process(Request request) {
        return request.process(this);
    }
}
