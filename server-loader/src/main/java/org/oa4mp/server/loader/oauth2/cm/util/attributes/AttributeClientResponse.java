package org.oa4mp.server.loader.oauth2.cm.util.attributes;


import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.storage.clients.Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:39 PM
 */
public class AttributeClientResponse implements Response {
    public AttributeClientResponse(Client client) {
        this.client = client;
    }

    public Client getClient() {
        return client;
    }

    Client client;

}
