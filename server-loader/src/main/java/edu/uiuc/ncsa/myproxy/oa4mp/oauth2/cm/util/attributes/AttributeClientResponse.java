package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes;


import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;

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
