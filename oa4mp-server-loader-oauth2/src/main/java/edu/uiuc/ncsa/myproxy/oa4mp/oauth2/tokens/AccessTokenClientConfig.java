package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractClientConfig;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Common configuration for all access tokens. This includes things like the lifetime,
 * issuer and what not.
 * <p>Created by Jeff Gaynor<br>
 * on 7/28/20 at  7:51 AM
 */
public class AccessTokenClientConfig extends AbstractClientConfig {
    public static String LIFETIME_KEY = "lifetime";
    public static String SUBJECT_KEY = "subject";
    public static String ISSUER_KEY = "issuer";
    public static String TYPE_KEY = "type";
    public static String VERSIONS_KEY = "versions";
    public static String AUDIENCE_KEY = "audience";
    public static String TEMPLATES_KEY = "templates";


    Long lifetime;
    String issuer;
    String subject;
    String type;
    List<String> versions;
    List<String> audience;
    List<AuthorizationPath> paths;


    @Override
    public void fromJSON(JSONObject jsonObject) {
        super.fromJSON(jsonObject);
        if (jsonObject.containsKey(LIFETIME_KEY)) {
            lifetime = jsonObject.getLong(LIFETIME_KEY);
        }
        if (jsonObject.containsKey(ISSUER_KEY)) {
            issuer = jsonObject.getString(ISSUER_KEY);
        }
        if (jsonObject.containsKey(SUBJECT_KEY)) {
            subject = jsonObject.getString(SUBJECT_KEY);
        }
        if (jsonObject.containsKey(TYPE_KEY)) {
            type = jsonObject.getString(TYPE_KEY);
        } else {
            throw new IllegalStateException("Error: Missing type for access token handler configuration");
        }
        if (jsonObject.containsKey(VERSIONS_KEY)) {
            versions = jsonObject.getJSONArray(VERSIONS_KEY);
        }
        if (jsonObject.containsKey(AUDIENCE_KEY)) {
            audience = jsonObject.getJSONArray(AUDIENCE_KEY);
        }
        if (jsonObject.containsKey(TEMPLATES_KEY)) {
            JSONArray array = jsonObject.getJSONArray(TEMPLATES_KEY);
            paths = new ArrayList<>();
            for(int i =0; i < array.size(); i++){
                AuthorizationPath ap = new AuthorizationPath(array.getJSONObject(i));
                paths.add(ap);
            }
            
        }
    }

    @Override
    public JSONObject toJSON() {
        JSONObject json = super.toJSON();
        if (lifetime != null) {
            json.put(LIFETIME_KEY, lifetime);
        }
        if (subject != null) {
            json.put(SUBJECT_KEY, subject);
        }
        if (type != null) {
            json.put(TYPE_KEY, type);

        }
        if (versions != null) {
            json.put(VERSIONS_KEY, versions);
        }
        if (paths != null) {
            JSONArray array = new JSONArray();
            for(AuthorizationPath ap: paths){
                array.add(ap.toJSON());
            }
            json.put(TEMPLATES_KEY,  array);
        }
        if (issuer != null) {
            json.put(ISSUER_KEY, issuer);
        }
        if (audience != null) {
            json.put(AUDIENCE_KEY, audience);
        }
        return json;
    }

    public Long getLifetime() {
        return lifetime;
    }

    public void setLifetime(Long lifetime) {
        this.lifetime = lifetime;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<String> getVersions() {
        return versions;
    }

    public void setVersions(List<String> versions) {
        this.versions = versions;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public List<AuthorizationPath> getPaths() {
        return paths;
    }

    public void setPaths(List<AuthorizationPath> paths) {
        this.paths = paths;
    }

    public static void main(String[] args) {
        AccessTokenClientConfig acc = new AccessTokenClientConfig();
        acc.setType("wlcg");
        acc.setSubject("${eppn}");
        acc.setIssuer("https://cilogon.org/fnal");
        acc.setLifetime(3600 * 24 * 11 * 1000L);// 11 days in ms
        ArrayList<String> aud = new ArrayList<>();
        aud.add("https://fnal.gov/serverA");
        aud.add("https://fnal.gov/serverB");
        aud.add("https://fnal.gov/${public_server}");
        acc.setAudience(aud);
        ArrayList<String> versions = new ArrayList<>();
        versions.add("1.0");
        acc.setVersions(versions);
        ArrayList paths = new ArrayList();
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_READ, "/home/${sub}"));
        System.out.println(paths.toString());
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_READ, "/home/${eppn}/${sub}"));
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_WRITE, "/home/${sub}"));
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_EXECUTE, "/home/${memberOf}/ingest.sh"));
        paths.add(new AuthorizationPath(SciTokenConstants.OPERATION_QUEUE, "/home/${memberOf}/serialize.sh"));
        acc.setPaths(paths);
        //  at.put(new AuthorizationTemplate("compute.create", ""));
        System.out.println(acc.toJSON().toString(1));

        AccessTokenClientConfig acc2 = new AccessTokenClientConfig();
        acc2.fromJSON(acc.toJSON());
        System.out.println(acc2.toJSON().toString(1));

    }
}
