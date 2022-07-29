package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.client.DelegationService;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 14, 2011 at  3:41:25 PM
 */
public class DelegationRequest extends BasicRequest {

    public Response process(Server server) {
        if (server instanceof DelegationService) {
            return ((DelegationService) server).processDelegationRequest(this);
        }
        return super.process(server);
    }

    /**
     * This request returns a response uri with all appropriate parameters. The base uri for the response is
     * included here.
     *
     * @return
     */
    public URI getBaseUri() {
        return baseUri;
    }

    public void setBaseUri(URI baseUri) {
        this.baseUri = baseUri;
    }

    URI baseUri;
}
