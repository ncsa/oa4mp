package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.security.core.util.BeanUtils;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * This is an entry for the {@link AuthorizationTemplates}. Each is keyed to an audience
 * and this is how permissions are found. An audience may be any string and may
 * include templates. Note that these templates have <i>nothing</i> to do with the
 * {@link edu.uiuc.ncsa.security.util.configuration.TemplateUtil} and its uses!
 * <p>Created by Jeff Gaynor<br>
 * on 8/2/18 at  2:41 PM
 */
public class AuthorizationTemplate {
    public AuthorizationTemplate(JSONObject json) {
        fromJSON(json);
    }

    public AuthorizationTemplate(String audience,
                                 Collection<AuthorizationPath> paths) {
        this.audience = audience;
        this.paths = paths;
    }

    String audience;
    Collection<AuthorizationPath> paths;

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }


    public Collection<AuthorizationPath> getPaths() {
        return paths;
    }

    public void setPaths(Collection<AuthorizationPath> paths) {
        this.paths = paths;
    }

    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(OA2Claims.AUDIENCE, audience);
        JSONArray array = new JSONArray();
        for (AuthorizationPath path : paths) {
            array.add(path.toJSON());
        }
        jsonObject.put("paths", array);
        return jsonObject;
    }

    public void fromJSON(JSONObject jsonObject) {
        audience = jsonObject.getString(OA2Claims.AUDIENCE);
        JSONArray x = jsonObject.getJSONArray("paths");
        paths = new LinkedList<>();
        for (int i = 0; i < x.size(); i++) {
            AuthorizationPath authorizationPath = new AuthorizationPath(x.getJSONObject(i));
            paths.add(authorizationPath);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AuthorizationTemplate)) return false;
        AuthorizationTemplate at = (AuthorizationTemplate) obj;
        if (!BeanUtils.checkEquals(at.audience, audience)) return false;
        if (at.getPaths().size() != getPaths().size()) return false;
        for (AuthorizationPath ap : getPaths()) {
            if (!at.getPaths().contains(ap)) return false;
        }
        return true;
    }

    public static void main(String[] args) {
        try {
            // This is a direct example to create the data structure for a template and
            // show what the JSON should be.
            // Note that the template does not check for redundant entries.
            List<AuthorizationPath> paths = new ArrayList<>();
            paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_READ, "/home/${sub}"));
            paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_READ, "/home/${eppn}/${sub}"));
            paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_WRITE, "/home/${sub}"));
            paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_EXECUTE, "/home/${memberOf}/ingest.sh"));
            paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_QUEUE, "/home/${memberOf}/serialize.sh"));
            AuthorizationTemplate template = new AuthorizationTemplate("https://foo.bigstate.edu", paths);
            System.out.println(template.toJSON().toString(1));

        } catch (Throwable t) {

        }
    }
}
