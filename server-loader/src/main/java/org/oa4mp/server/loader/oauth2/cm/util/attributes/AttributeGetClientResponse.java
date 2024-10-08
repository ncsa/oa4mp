package org.oa4mp.server.loader.oauth2.cm.util.attributes;

import org.oa4mp.delegation.common.storage.clients.Client;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/10/17 at  12:35 PM
 */
public class AttributeGetClientResponse extends AttributeClientResponse {
    public AttributeGetClientResponse(Client client, List<String> attributes) {
        super(client);
        this.attributes = attributes;
    }

    public List<String> getAttributes() {
        return attributes;
    }

    List<String> attributes;
}
