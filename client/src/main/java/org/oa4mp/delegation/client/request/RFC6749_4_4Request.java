package org.oa4mp.delegation.client.request;

import org.oa4mp.delegation.common.storage.clients.Client;

import java.util.Map;

public class RFC6749_4_4Request extends BasicRequest{
    public RFC6749_4_4Request(Client client, Map<String, String> parameters, String keyID) {
        super(client, parameters, keyID);
    }

    public RFC6749_4_4Request() {
    }
}
