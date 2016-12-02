package edu.uiuc.ncsa.co.util.client;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  1:02 PM
 */
public class CreateResponse extends ClientResponse{
    public CreateResponse(OA2Client client) {
        this.client = client;
    }

    OA2Client client;

    public OA2Client getClient() {
        return client;
    }
}
