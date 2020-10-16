package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
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
public class AccessTokenConfig extends AbstractPayloadConfig {
    public static String LIFETIME_KEY = "lifetime";
    public static String SUBJECT_KEY = "subject";
    public static String ISSUER_KEY = "issuer";
    public static String AUDIENCE_KEY = "audience";
    public static String TEMPLATES_KEY = "templates";


    Long lifetime = -1L;
    String issuer;
    String subject;
    List<String> audience = new ArrayList<>();
    AuthorizationTemplates templates = new AuthorizationTemplates();


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

        if (jsonObject.containsKey(AUDIENCE_KEY)) {
            Object obj = jsonObject.get(AUDIENCE_KEY);
            DebugUtil.trace(this, "Got audience=" + obj);
            if (obj instanceof JSONArray) {
                audience = (List<String>) obj;

            } else {
                ArrayList x = new ArrayList();
                x.add(obj.toString());
                audience = x;

            }
        }
        if (jsonObject.containsKey(TEMPLATES_KEY)) {
            templates = new AuthorizationTemplates();
            templates.fromJSON(jsonObject.getJSONArray(TEMPLATES_KEY));
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

        if (templates != null) {

            json.put(TEMPLATES_KEY, templates.toJSON());
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


    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public AuthorizationTemplates getTemplates() {
        return templates;
    }

    public void setTemplates(AuthorizationTemplates templates) {
        this.templates = templates;
    }

    public static void main(String[] args) {
        AccessTokenConfig acc = new AccessTokenConfig();
        acc.setId(Long.toString(System.currentTimeMillis(), 16));
        acc.setType("scitoken");
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
        AuthorizationTemplate template = new AuthorizationTemplate("https://fnal.gov/serverA", paths);
        AuthorizationTemplates authorizationTemplates = new AuthorizationTemplates();
        authorizationTemplates.put(template);
        acc.setTemplates(authorizationTemplates);

        //  at.put(new AuthorizationTemplate("compute.create", ""));
        System.out.println(acc.toJSON().toString(1));

        AccessTokenConfig acc2 = new AccessTokenConfig();
        acc2.fromJSON(acc.toJSON());
        System.out.println(acc2.toJSON().toString(1));

    }
}
