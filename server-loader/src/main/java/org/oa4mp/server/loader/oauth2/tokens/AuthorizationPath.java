package org.oa4mp.server.loader.oauth2.tokens;

import edu.uiuc.ncsa.security.core.util.BeanUtils;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/11/18 at  6:25 PM
 */
public class AuthorizationPath {
    String operation;
    String path = null;

    public boolean isExtensible() {
        return extensible;
    }

    public void setExtensible(boolean extensible) {
        this.extensible = extensible;
    }

    boolean extensible = true;

    public String getOperation() {
        return operation;
    }

    public String getPath() {
        return path;
    }

    public boolean hasPath() {
        return !StringUtils.isTrivial(path);
    }

    public AuthorizationPath(JSONObject json) {
        fromJSON(json);
    }


    public AuthorizationPath(String operation,
                             String path,
                             boolean isExtensible) {
        this.operation = operation;
        this.path = path;
        this.extensible = isExtensible;

    }

    /**
     * Constructor for a fixed scope (e.g. compute.modify) that has no path and should
     * never be downscoped.
     * @param operation
     */
    public AuthorizationPath(String operation) {
        this(operation, null, false);
    }
    public AuthorizationPath(String operation, String path) {
        this(operation, path, true);
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(AuthorizationTemplates.OPERATION_KEY, operation);
        if (hasPath()) {
            jsonObject.put(AuthorizationTemplates.PATH_KEY, path);
        }
        jsonObject.put(AuthorizationTemplates.EXTENSIBLE_KEY, extensible);
        return jsonObject;
    }

    public void fromJSON(JSONObject j) {
        operation = j.getString(AuthorizationTemplates.OPERATION_KEY);
        if(j.containsKey(AuthorizationTemplates.EXTENSIBLE_KEY)){
               this.extensible = j.getBoolean(AuthorizationTemplates.EXTENSIBLE_KEY);
        }
        if (j.containsKey(AuthorizationTemplates.PATH_KEY)) {
            path = j.getString(AuthorizationTemplates.PATH_KEY);
        }else{
            this.extensible = false;
        }

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

        } else {
            operation = template.substring(0, colonIndex);
            path = template.substring(colonIndex + 1);
        }
    }

    @Override
    public String toString() {
        return "AuthorizationPath{" +
                "operation='" + operation + '\'' +
                ", path='" + path + '\'' +
                ", extensible=" + extensible +
                '}';
    }

    /**
     * Return this as path representation of this object. Note that this is used
     * in comparisons, while {@link #toString()} is used for printing and such.
     * @return
     */
    public String toPath(){
          return operation +  (StringUtils.isTrivial(path)?"":(":" + path));
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthorizationPath)) return false;
        AuthorizationPath ap = (AuthorizationPath) obj;
        if (!BeanUtils.checkEquals(ap.operation, operation)) return false;
        if (!BeanUtils.checkEquals(ap.path, path)) return false;
        return ap.extensible != this.extensible;
    }

}
