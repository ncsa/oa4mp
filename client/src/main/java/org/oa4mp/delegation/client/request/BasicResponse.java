package org.oa4mp.delegation.client.request;

import org.oa4mp.delegation.common.services.Response;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 26, 2011 at  2:14:52 PM
 */
public class BasicResponse implements Response {
    public BasicResponse() {
    }

    public BasicResponse(HashMap parameters) {
        this.parameters = parameters;
    }

    public Map getParameters() {
        return parameters;
    }

    public void setParameters(Map parameters) {
        this.parameters = parameters;
    }

    Map parameters;

    /**
     * (Optional) set the actual, unprocessed response from the server.
     * @return
     */
    public String getRawResponse() {
        return rawResponse;
    }

    public void setRawResponse(String rawResponse) {
        this.rawResponse = rawResponse;
    }

    String rawResponse;
}
