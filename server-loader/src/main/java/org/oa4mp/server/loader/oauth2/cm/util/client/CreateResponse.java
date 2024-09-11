package org.oa4mp.server.loader.oauth2.cm.util.client;


import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  1:02 PM
 */
public class CreateResponse extends ClientResponse {
    public CreateResponse(OA2Client client, String secret) {
        this.secret = secret;
        this.client = client;
    }

    OA2Client client;

    public OA2Client getClient() {
        return client;
    }

    public String getSecret() {
        return secret;
    }

    String secret;
}
