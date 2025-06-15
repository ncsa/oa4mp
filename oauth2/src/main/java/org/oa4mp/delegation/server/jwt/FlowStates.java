package org.oa4mp.delegation.server.jwt;

import net.sf.json.JSONObject;

import static org.oa4mp.delegation.server.jwt.FlowType.*;

/**
 * A container for the states that are permitted. These change the control flow, e.g. access no refresh tokens
 * if a certain condition is met. The default for all of these is true, meaning that everything is allowed.
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/18 at  1:19 PM
 */
public class FlowStates {
    public FlowStates(JSONObject json) {
        fromJSON(json);
    }


    public FlowStates() {
    }

    public boolean acceptRequests = true;
    public boolean accessToken = true;
    public boolean getCert = true;
    public boolean getClaims = true;
    public boolean idToken = true;
    public boolean refreshToken = true;
    public boolean userInfo = true;
    public boolean at_do_templates = true;

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(ACCEPT_REQUESTS.getValue(), acceptRequests);
        jsonObject.put(ACCESS_TOKEN.getValue(), accessToken);
        jsonObject.put(GET_CERT.getValue(), getCert);
        jsonObject.put(GET_CLAIMS.getValue(), getClaims);
        jsonObject.put(ID_TOKEN.getValue(), idToken);
        jsonObject.put(REFRESH_TOKEN.getValue(), refreshToken);
        jsonObject.put(USER_INFO.getValue(), userInfo);
        jsonObject.put(AT_DO_TEMPLATES.getValue(), at_do_templates);
        return jsonObject;
    }

    public void fromJSON(JSONObject jsonObject) {
        acceptRequests = jsonObject.getBoolean(ACCEPT_REQUESTS.getValue());
        accessToken = jsonObject.getBoolean(ACCESS_TOKEN.getValue());
        getCert = jsonObject.getBoolean(GET_CERT.getValue());
        getClaims = jsonObject.getBoolean(GET_CLAIMS.getValue());
        idToken = jsonObject.getBoolean(ID_TOKEN.getValue());
        refreshToken = jsonObject.getBoolean(REFRESH_TOKEN.getValue());
        userInfo = jsonObject.getBoolean(USER_INFO.getValue());
        if(jsonObject.containsKey(AT_DO_TEMPLATES.getValue())) {
            // Some old, serialized versions (such as with long-term refresh tokens)
            // Do not have this. Rather than an NPE, this will fail with a
            // message like
            // net.sf.json.JSONException: JSONObject["at_do_templates"] is not a Boolean.
            at_do_templates = jsonObject.getBoolean(AT_DO_TEMPLATES.getValue());
        }else{
            at_do_templates = true;

        }
    }

    @Override
    public String toString() {
        return "FlowStates{" +
                "acceptRequests=" + acceptRequests +
                ", accessToken=" + accessToken +
                ", getCert=" + getCert +
                ", getClaims=" + getClaims +
                ", idToken=" + idToken +
                ", refreshToken=" + refreshToken +
                ", do access token templates="  + at_do_templates +
                ", userInfo=" + userInfo +
                '}';
    }
}
