package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows;

import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.logic.FunctorMap;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType.*;

/**
 * A container for the states that are permitted. These change the control flow, e.g. access no refresh tokens
 * if a certain condition is met. The default for all of these is true, meaning that
 * <p>Created by Jeff Gaynor<br>
 * on 3/26/18 at  1:19 PM
 */
public class FlowStates {
    public FlowStates(JSONObject json) {
        fromJSON(json);
    }

    public FlowStates(FunctorMap functorMap) {
        super();
        updateValues(functorMap);
    }

    /**
     * The contract for this method is that the values of this object (default is all true) will be
     * updated based on the functor map. Unless the values are explicitly changed, they remain.
     * @param functorMap
     */
    public void updateValues(FunctorMap functorMap) {
        acceptRequests = findValue(functorMap, ACCEPT_REQUESTS, acceptRequests);
        accessToken = findValue(functorMap, ACCESS_TOKEN, accessToken);
        getCert = findValue(functorMap, GET_CERT, getCert);
        getClaims = findValue(functorMap, GET_CLAIMS, getClaims);
        idToken = findValue(functorMap, ID_TOKEN, idToken);
        refreshToken = findValue(functorMap, REFRESH_TOKEN, refreshToken);
        userInfo = findValue(functorMap, USER_INFO, userInfo);
    }

    protected boolean findValue(FunctorMap functorMap, FlowType type, boolean previousValue) {
        if (functorMap.containsKey(type)) {
            JFunctor jf = functorMap.get(type).get(0);
            return Boolean.parseBoolean((String) jf.getResult());
        }
        return previousValue; //default
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

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(ACCEPT_REQUESTS.getValue(), acceptRequests);
        jsonObject.put(ACCESS_TOKEN.getValue(), accessToken);
        jsonObject.put(GET_CERT.getValue(), getCert);
        jsonObject.put(GET_CLAIMS.getValue(), getClaims);
        jsonObject.put(ID_TOKEN.getValue(), idToken);
        jsonObject.put(REFRESH_TOKEN.getValue(), refreshToken);
        jsonObject.put(USER_INFO.getValue(), userInfo);
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
                ", userInfo=" + userInfo +
                '}';
    }
}
