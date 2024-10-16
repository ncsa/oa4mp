package org.oa4mp.delegation.client.request;

import net.sf.json.JSONObject;

public class RFC6749_4_4_Response extends BasicResponse{
    /**
     * Conveneience method that casts the parameter map to its underlying
     * JSON object.
     * @return
     */
    public JSONObject getJSON() {
        return (JSONObject) getParameters();
    }
}
