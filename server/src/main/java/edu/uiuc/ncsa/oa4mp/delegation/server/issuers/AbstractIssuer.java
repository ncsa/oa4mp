package edu.uiuc.ncsa.oa4mp.delegation.server.issuers;

import org.oa4mp.delegation.common.services.AddressableServer;
import org.oa4mp.delegation.common.services.Request;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.token.TokenForge;

import java.net.URI;

/**
 * An issuer creates and issues something (usually tokens and protected assets). We could
 * have called these servers or services as well but the words are so over-used that it is too
 * hard to keep them straight. Generally a client has a model of a service that it talks to
 * called a service. On the server itself, the model of the thing that does the work is
 * an issuer.
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  11:49:42 AM
 */
public abstract class AbstractIssuer implements AddressableServer {
    protected AbstractIssuer(TokenForge tokenForge, URI address) {
        this.address = address;
        this.tokenForge = tokenForge;
    }


    /**
     * The actual physical address where this server resides.
     *
     * @return
     */
    public URI getAddress() {
        return address;
    }

    URI address;

    public Response process(Request request) {
        return request.process(this);
    }
  protected  TokenForge tokenForge;
}
