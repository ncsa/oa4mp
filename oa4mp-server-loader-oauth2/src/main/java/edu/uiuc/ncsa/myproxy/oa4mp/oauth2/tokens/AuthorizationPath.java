package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.security.core.util.BeanUtils;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/11/18 at  6:25 PM
 */
public class AuthorizationPath {
    String operation;
    String path;

    public AuthorizationPath(JSONObject json) {
        fromJSON(json);
    }

    public AuthorizationPath(String template) {
        super();
        fromString(template);

    }
    public AuthorizationPath(String operation, String path) {
        this.operation = operation;
        this.path = path;
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("operation", operation);
        jsonObject.put("path", path);
        return jsonObject;
    }

    public void fromJSON(JSONObject j) {
        operation = j.getString("operation");
        path = j.getString("path");
    }

    /**
     * This allows populating this from a single string of the form operation:path
     *
     * @param template
     */
    public void fromString(String template) {
        int colonIndex = template.indexOf(":");
        if (colonIndex < 0) {
       //     throw new IllegalArgumentException("Error: template \"" + template + "\" cannot be parsed.");
            // edge case: no path (which is optional in some specs, such as WLCG.)
            operation = template;
            path = "";

        }                                             else {
            operation = template.substring(0, colonIndex);
            path = template.substring(colonIndex + 1);
        }
    }

    @Override
    public String toString() {
        return operation + ":" + path;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthorizationPath)) return false;
        AuthorizationPath ap = (AuthorizationPath) obj;
        if (!BeanUtils.checkEquals(ap.operation, operation)) return false;
        if (!BeanUtils.checkEquals(ap.path, path)) return false;
        return true;
    }
    public static void main(String[] args){
        String template = "read:/public/${user}/***";
        AuthorizationPath at = new AuthorizationPath(template);
        // The result should look like the argument, just checking that it parsed ok.
        System.out.println(at);
        at = new AuthorizationPath("compute.queue");
        System.out.println(at);
    }
}
