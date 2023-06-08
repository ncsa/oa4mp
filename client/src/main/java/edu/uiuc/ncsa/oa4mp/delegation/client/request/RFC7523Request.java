package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/6/23 at  3:05 PM
 */
public class RFC7523Request extends BasicRequest{
    public RFC7523Request() {
    }

    public RFC7523Request(Client client, String kid, Map<String, String> parameters) {
        super(client,  parameters, kid);
    }
}
