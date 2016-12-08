package edu.uiuc.ncsa.co.util.client;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/5/16 at  2:06 PM
 */
public class GetResponse extends ClientResponse{
    public GetResponse(OA2Client client, boolean isApproved) {
        this.client = client;
        this.approved = isApproved;
    }

    public OA2Client getClient() {
        return client;
    }

    OA2Client client;

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[client=" + client + "]";
    }

    public boolean isApproved() {
        return approved;
    }

    boolean approved;
}
