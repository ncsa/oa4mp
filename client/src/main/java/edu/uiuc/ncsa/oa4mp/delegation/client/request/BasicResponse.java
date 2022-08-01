package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;

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
}
