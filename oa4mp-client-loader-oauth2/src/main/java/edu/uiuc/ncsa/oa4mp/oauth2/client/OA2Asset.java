package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import net.sf.json.JSONObject;

import java.text.ParseException;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  12:04 PM
 */
public class OA2Asset extends Asset {
    public OA2Asset(Identifier identifier) {
        super(identifier);
    }

    AccessTokenImpl accessToken;
    RefreshTokenImpl refreshToken;

    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    Date issuedAt = new Date();

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    String state;

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    String nonce;

    public AccessTokenImpl getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessTokenImpl accessToken) {
        this.accessToken = accessToken;
    }


    public RefreshTokenImpl getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshTokenImpl refreshToken) {
        this.refreshToken = refreshToken;
    }

    protected String REFRESH_TOKEN_KEY = "refresh_token";
    protected String ACCESS_TOKEN_KEY = "access_token";
    protected String STATE_KEY = "state";
    protected String NONCE_KEY = "nonce";
    protected String ISSUED_AT_KEY = "issued_at";

    @Override
    public JSONObject toJSON() {
        JSONObject json = super.toJSON();
        if (!StringUtils.isTrivial(getNonce())) {
            json.put(NONCE_KEY, getNonce());
        }
        if (!StringUtils.isTrivial(getState())) {
            json.put(STATE_KEY, getState());
        }
        if (getAccessToken() != null) {
            json.put(ACCESS_TOKEN_KEY, getAccessToken().toJSON());
        }
        if (getRefreshToken() != null) {
            json.put(REFRESH_TOKEN_KEY, getRefreshToken().toJSON());
        }
        if (getIssuedAt() != null) {
            json.put(ISSUED_AT_KEY, Iso8601.date2String(getIssuedAt()));
        }
        return json;
    }

    @Override
    public void fromJSON(JSONObject jsonObject) {
        super.fromJSON(jsonObject);
        if (jsonObject.containsKey(NONCE_KEY)) {
            setNonce(jsonObject.getString(NONCE_KEY));
        }
        if (jsonObject.containsKey(STATE_KEY)) {
            setState(jsonObject.getString(STATE_KEY));
        }
        if (jsonObject.containsKey(ACCESS_TOKEN_KEY)) {
            AccessTokenImpl at = new AccessTokenImpl("");
            at.fromJSON(jsonObject.getJSONObject(ACCESS_TOKEN_KEY));
            setAccessToken(at);
        }
        if (jsonObject.containsKey(REFRESH_TOKEN_KEY)) {
            RefreshTokenImpl rt = new RefreshTokenImpl("");
            rt.fromJSON(jsonObject.getJSONObject(REFRESH_TOKEN_KEY));
            setRefreshToken(rt);
        }
        if (jsonObject.containsKey(ISSUED_AT_KEY)) {
            try {
                setCreationTime(Iso8601.string2Date(jsonObject.getString(ISSUED_AT_KEY)).getTime());
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
    }
}
