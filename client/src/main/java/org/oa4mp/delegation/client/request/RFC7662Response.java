package org.oa4mp.delegation.client.request;

import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  6:16 AM
 */
public class RFC7662Response extends BasicResponse{
    public JSONObject getResponse() {
        return response;
    }

    public void setResponse(JSONObject response) {
        this.response = response;
    }

    JSONObject response;
}
