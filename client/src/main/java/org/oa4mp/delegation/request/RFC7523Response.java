package org.oa4mp.delegation.request;

import org.oa4mp.delegation.common.token.impl.IDTokenImpl;
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

    public IDTokenImpl getIdToken() {
        return idToken;
    }

    public void setIdToken(IDTokenImpl idToken) {
        this.idToken = idToken;
    }

    IDTokenImpl idToken;
}

