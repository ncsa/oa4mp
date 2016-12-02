package edu.uiuc.ncsa.co.util.attributes;

import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.storage.Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:39 PM
 */
public class AttributeResponse implements Response {
    public AttributeResponse(Client client) {
        this.client = client;
    }

    public Client getClient() {
        return client;
    }

    Client client;

}
