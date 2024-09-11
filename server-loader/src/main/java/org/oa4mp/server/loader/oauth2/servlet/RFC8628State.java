package org.oa4mp.server.loader.oauth2.servlet;

import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;

import java.net.URI;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/21 at  4:23 PM
 */
public class RFC8628State {
    String USER_CODE_KEY = "user_code";
    String DEVICE_CODE_KEY = "device_code";
    String LIFETIME_KEY = "lifetime";
    String ISSUED_AT_KEY = "issued_at";
    String LAST_TRY_KEY = "last_try";
    String FIRST_TRY_KEY = "first_try";
    String IS_VALID_KEY = "is_valid";
    String ORIGINAL_SCOPES_KEY = "original_scopes";

    public String userCode = null;
    public URI deviceCode = null;
    public long lifetime = -1L;
    public long issuedAt = -1L;
    public long lastTry = -1L;
    public long interval = -1L;
    // Used in the token endpoint. Allow the first try asap, then start waiting
    public boolean firstTry = true;
    /**
     * If the user finished logging in, hence making the flow valid.
     */
    public boolean valid = false;

    String INTERVAL_KEY = "interval";
    /**
     * The original string passed in the request.
     */
    public String originalScopes = "";

    public void fromJSON(JSONObject jsonObject) {
        if (jsonObject.containsKey(USER_CODE_KEY)) {
            userCode = jsonObject.getString(USER_CODE_KEY);
        }
        if (jsonObject.containsKey(DEVICE_CODE_KEY)) {
            deviceCode = URI.create(jsonObject.getString(DEVICE_CODE_KEY));
        }
        if (jsonObject.containsKey(LIFETIME_KEY)) {
            lifetime = jsonObject.getLong(LIFETIME_KEY);
        }
        if (jsonObject.containsKey(ISSUED_AT_KEY)) {
            issuedAt = jsonObject.getLong(ISSUED_AT_KEY);
        }
        if (jsonObject.containsKey(ORIGINAL_SCOPES_KEY)) {
            originalScopes = jsonObject.getString(ORIGINAL_SCOPES_KEY);
        }

        if (jsonObject.containsKey(LAST_TRY_KEY)) {
            lastTry = jsonObject.getLong(LAST_TRY_KEY);
        }
        if (jsonObject.containsKey(FIRST_TRY_KEY)) {
            firstTry = jsonObject.getBoolean(FIRST_TRY_KEY);
        }

        if (jsonObject.containsKey(INTERVAL_KEY)) {
            interval = jsonObject.getLong(INTERVAL_KEY);
        }
        valid = jsonObject.getBoolean(IS_VALID_KEY);
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(IS_VALID_KEY, valid); //always there
        jsonObject.put(FIRST_TRY_KEY, firstTry); //always there

        if (!isTrivial(userCode)) {
            jsonObject.put(USER_CODE_KEY, userCode);
        }
        if (deviceCode != null) {
            jsonObject.put(DEVICE_CODE_KEY, deviceCode.toString());
        }
        if (0 < lastTry) {
            jsonObject.put(LAST_TRY_KEY, lastTry);
        }
        if (!StringUtils.isTrivial(originalScopes)) {
            jsonObject.put(ORIGINAL_SCOPES_KEY, originalScopes);
        }

        if (0 < lifetime) {
            jsonObject.put(LIFETIME_KEY, lifetime);
        }
        if (0 < issuedAt) {
            jsonObject.put(ISSUED_AT_KEY, issuedAt);
        }
        if (0 < interval) {
            jsonObject.put(INTERVAL_KEY, interval);
        }

        return jsonObject;
    }

    public boolean isExpired() {
        return issuedAt + lifetime < System.currentTimeMillis();
    }
}
