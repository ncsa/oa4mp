package edu.uiuc.ncsa.oa4mp.delegation.client.request;

import net.sf.json.JSONObject;

import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/6/23 at  3:05 PM
 */
public class RFC7523Response extends BasicResponse{
    public RFC7523Response() {
    }

    public RFC7523Response(HashMap parameters) {
        super(parameters);
    }

    public JSONObject getResponse() {
        return response;
    }

    public void setResponse(JSONObject response) {
        this.response = response;
    }

    JSONObject response;

    public JSONObject getIdToken() {
        return idToken;
    }

    public void setIdToken(JSONObject idToken) {
        this.idToken = idToken;
    }

    JSONObject idToken;
}

