package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.qdl.scripting.AnotherJSONUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/30/20 at  10:00 AM
 */
public class SciTokenClientConfig extends AccessTokenClientConfig {
    public static String USERNAME_CLAIM_KEY = "usernameClaimKey";
    public static String TEMPLATES_KEY = "templates";

    public void fromJSON(JSONObject jsonObject) {
        if (jsonObject.containsKey(USERNAME_CLAIM_KEY)) {
            usernameClaimKey = jsonObject.getString(USERNAME_CLAIM_KEY);
        }
        if (jsonObject.containsKey(TEMPLATES_KEY)) {
            authorizationTemplates = new AuthorizationTemplates();
            authorizationTemplates.fromJSON(jsonObject.getJSONArray(TEMPLATES_KEY));
        }
        setScriptSet(AnotherJSONUtil.createScripts(jsonObject));

    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        if (!StringUtils.isTrivial(usernameClaimKey)) {
            jsonObject.put(USERNAME_CLAIM_KEY, usernameClaimKey);
        }
        if (!authorizationTemplates.isEmpty()) {
            jsonObject.put(TEMPLATES_KEY, authorizationTemplates.toJSON());
        }
        return jsonObject;
    }

    /**
     * If the user wants to use the ${user} template rather than accessing the claim name directly,
     * they <i>could</i> set it here.
     * @return
     */
    public String getUsernameClaimKey() {
        return usernameClaimKey;
    }

    public void setUsernameClaimKey(String usernameClaimKey) {
        this.usernameClaimKey = usernameClaimKey;
    }

    String usernameClaimKey;

    public AuthorizationTemplates getAuthorizationTemplates() {
        return authorizationTemplates;
    }

    public void setAuthorizationTemplates(AuthorizationTemplates authorizationTemplates) {
        this.authorizationTemplates = authorizationTemplates;
    }

    AuthorizationTemplates authorizationTemplates;

    @Override
    public ScriptSet getScriptSet() {
        return null;
    }
}
