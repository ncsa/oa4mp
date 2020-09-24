package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


/**
 * This keys off the audience. The {@link AuthorizationTemplate} contains multiple paths. At this point
 * we have a single one of these per audience, i.e. the audience is the unique key.
 * <p>Created by Jeff Gaynor<br>
 * on 8/2/18 at  2:42 PM
 */
public class AuthorizationTemplates extends HashMap<String, AuthorizationTemplate> {
    public static final String OPERATION_KEY = "op";
    public static final String PATH_KEY = "path";

    public AuthorizationTemplate put(AuthorizationTemplate value) {
        return super.put(value.getAudience(), value);
    }

    /**
     * the actual argument is assumed to be a JSON array of templates. If there si a single template,
     * it is wrapped in a JSONArray and passed to {@link #fromJSON(JSONArray)}.
     *
     * @param json
     */
    public void fromJSON(JSON json) {
        if (json.isArray()) {
            fromJSON((JSONArray) json);
        } else {
            JSONArray array = new JSONArray();
            array.add(json);
            fromJSON(array);
        }
    }

    /**
     * This actually does the work. The array is assumed to be an array of serialized {@link AuthorizationTemplate} objects.
     *
     * @param array
     */
    public void fromJSON(JSONArray array) {
        for (int i = 0; i < array.size(); i++) {
            JSONObject json = array.getJSONObject(i);
            AuthorizationTemplate at = new AuthorizationTemplate(json);
            put(at.getAudience(), at);
        }

    }

    /**
     * Create this from a {@link JSON} object. If this is a single {@link JSONObject}, then
     * it is assumed to be a {@link AuthorizationTemplate}. If it is {@link JSONArray}
     * then it is assumed to be a collection of them.
     *
     * @param rawJSON
     */
    public void fromJSON(String rawJSON) {
        JSONArray array = null;
        try {
            array = JSONArray.fromObject(rawJSON);
        } catch (Throwable t) {
            // rock on
        }
        if (array == null) {
            try {
                JSONObject json = JSONObject.fromObject(rawJSON);
                array = new JSONArray();
                array.add(json);
            } catch (Throwable t) {
                // rock on
            }
        }

        if (array == null) {
            throw new GeneralException("Error: Could not parse string into JSON.");
        }
        fromJSON(array);
    }

    /**
     * Turn the contents of this object into a JSON object
     *
     * @return
     */
    public JSONArray toJSON() {
        JSONArray array = new JSONArray();
        for (String audience : keySet()) {
            AuthorizationTemplate at = get(audience);
            array.add(at.toJSON());
        }
        return array;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthorizationTemplates)) {
            return false;
        }
        AuthorizationTemplates ats = (AuthorizationTemplates) obj;
        if (ats.size() != size()) return false;
        for (String key : keySet()) {
            AuthorizationTemplate thatAT = ats.get(key);
            AuthorizationTemplate thisAT = get(key);
            if (!thisAT.equals(thatAT)) {
                return false;
            }

        }
        return true;
    }

    public static void main(String[] args) {
        List<AuthorizationPath> paths = new ArrayList<>();
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_READ, "/home/${sub}"));
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_WRITE, "/home/${sub}"));
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_QUEUE, "/home/${memberOf}/serialize.sh"));
        AuthorizationTemplate template = new AuthorizationTemplate("https://foo.bigstate.edu", paths);
        AuthorizationTemplates authorizationTemplates = new AuthorizationTemplates();
        authorizationTemplates.put(template);
        // And another one
        paths = new ArrayList<>();
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_READ, "/home/${eppn}/${sub}"));
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_EXECUTE, "/home/${memberOf}/ingest.sh"));
        template = new AuthorizationTemplate("https://bar.bigstate.edu", paths);
        authorizationTemplates.put(template);

        System.out.println(authorizationTemplates.toJSON().toString(1));

    }
}
