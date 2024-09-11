package org.oa4mp.delegation.request;

import org.oa4mp.delegation.common.services.Request;
import org.oa4mp.delegation.common.services.Response;
import org.oa4mp.delegation.common.services.Server;
import org.oa4mp.delegation.common.storage.clients.Client;

import java.util.HashMap;
import java.util.Map;

/**
 * <h2>Usage</h2>
 * Clients will need to send along parameters in their requests. This is done with a standard {@link Map}.
 * The Map will have every key value pair appended to the request. No formatting or other processing
 * will be done to these so be sure to do this first. (2023-06-08) added support for RFC 7523
 * JWK authentication.
 * <p><br>
 * <p>Created by Jeff Gaynor<br>
 * on Apr 26, 2011 at  1:58:56 PM
 */
public abstract class BasicRequest implements Request {
    /**
     * The client that is making this request.
     *
     * @return
     */
    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    Client client;

    public String getKeyID() {
        return keyID;
    }

    public void setKeyID(String keyID) {
        this.keyID = keyID;
    }

    String keyID = null;
    public boolean hasKeyID(){
        return keyID != null;
    }
    public BasicRequest() {
    }

    public BasicRequest(Client client,
                        Map<String, String> parameters,
                        String keyID) {
        this.client = client;
        this.parameters = parameters;
        this.keyID = keyID;
    }

    public Response process(Server server) {
        // Default is to blow up in case someone gets one of these by accident.
        throw new RuntimeException("Error: not implemented");
    }

    /**
     * Additional parameters that the request is to send along to the server. These are key/value pairs
     * and will be treated as strings.
     *
     * @return
     */
    public Map<String, String> getParameters() {
        if (parameters == null) {
            parameters = new HashMap<String, String>();
        }
        return parameters;
    }

    /**
     * @param parameters
     * @see #getParameters() for what this is and does.
     */
    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    Map parameters;
}
