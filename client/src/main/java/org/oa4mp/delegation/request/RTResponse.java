package org.oa4mp.delegation.request;

import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.IDTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenFactory;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/14 at  11:19 AM
 */
public class RTResponse extends ATResponse {

    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String VERSION = "version";
    public static final String TYPE = "type";
    public static final String PARAMETERS = "parameters";
    public static final String ID_TOKEN = "id_token";

    public RTResponse(AccessTokenImpl accessToken) {
        super(accessToken);
    }

    public RTResponse(AccessTokenImpl accessToken,
                      RefreshTokenImpl refreshToken,
                      IDTokenImpl idToken) {
        super(accessToken);
        this.refreshToken = refreshToken;
        this.idToken = idToken;
    }

    public RefreshTokenImpl getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshTokenImpl refreshToken) {
        this.refreshToken = refreshToken;
    }

    RefreshTokenImpl refreshToken = null;

    public boolean hasRefreshToken() {
        return refreshToken != null;
    }

    public IDTokenImpl getIdToken() {
        return idToken;
    }

    public void setIdToken(IDTokenImpl idToken) {
        this.idToken = idToken;
    }

    IDTokenImpl idToken = null;

    public boolean hasIDToken() {
        return idToken != null;
    }

    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        json.put(TYPE, "rt_response");
        json.put(VERSION, "1.0");
        json.put(ACCESS_TOKEN, getAccessToken().toJSON().toString());
        if (hasRefreshToken()) {
            json.put(REFRESH_TOKEN, getRefreshToken().toJSON().toString());
        }
        if (hasIDToken()) {
            json.put(ID_TOKEN, getIdToken().toJSON().toString());
        }
        if (!parameters.isEmpty()) {
            JSONObject p = new JSONObject();
            p.putAll(parameters);
            json.put(PARAMETERS, p.toString());
        }
        return json;
    }

    public void fromJSON(JSONObject json) {
        if (!json.containsKey(TYPE)) {
            throw new IllegalArgumentException("unknown type for RTResponse deserialization");
        }
        if (!json.getString(TYPE).equals("rt_response")) {
            throw new IllegalArgumentException("unknown type for RTResponse deserialization");
        }
        if (json.getString(VERSION).equals("1.0")) {
            setAccessToken(TokenFactory.createAT(JSONObject.fromObject(json.getString(ACCESS_TOKEN))));
            if (json.containsKey(REFRESH_TOKEN)) {
                setRefreshToken(TokenFactory.createRT(JSONObject.fromObject(json.getString(REFRESH_TOKEN))));
            }
            if (json.containsKey(ID_TOKEN)) {
                setIdToken(TokenFactory.createIDT(JSONObject.fromObject(json.getString(ID_TOKEN))));
            }
            if (json.containsKey(PARAMETERS)) {
                parameters = JSONObject.fromObject(json.getString(PARAMETERS));
            }
            return;
        }
        throw new IllegalArgumentException("unknown version for RTResponse deserialization");
    }
}
