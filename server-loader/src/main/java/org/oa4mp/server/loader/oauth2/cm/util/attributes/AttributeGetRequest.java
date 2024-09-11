package org.oa4mp.server.loader.oauth2.cm.util.attributes;


import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:32 PM
 */
public class AttributeGetRequest extends AttributeRequest{
    public AttributeGetRequest(
                               AdminClient adminClient,
                               OA2Client client,
                               List<String> attributes) {
        super(adminClient,client);
        this.attributes = attributes;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    List<String> attributes;



}
