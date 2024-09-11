package org.oa4mp.server.loader.oauth2.tokens;

import net.sf.json.JSONObject;

import java.util.ArrayList;

import static org.oa4mp.server.loader.oauth2.claims.AbstractAccessTokenHandler.AT_DEFAULT_HANDLER_TYPE;

/**
 * Common configuration for all access tokens. This includes things like the lifetime,
 * issuer and what not.
 * <p>Created by Jeff Gaynor<br>
 * on 7/28/20 at  7:51 AM
 */
public class AccessTokenConfig extends AbstractCommonATandRTConfig {
    public static String TEMPLATES_KEY = "templates";

    AuthorizationTemplates templates = new AuthorizationTemplates();


    @Override
    public void fromJSON(JSONObject jsonObject) {
        super.fromJSON(jsonObject);
        if (jsonObject.containsKey(TEMPLATES_KEY)) {
            templates = new AuthorizationTemplates();
            templates.fromJSON(jsonObject.getJSONArray(TEMPLATES_KEY));
        }
    }

    @Override
    public JSONObject toJSON() {
        JSONObject json = super.toJSON();
        if (templates != null) {
            json.put(TEMPLATES_KEY, templates.toJSON());
        }
        return json;
    }



    public AuthorizationTemplates getTemplates() {
        return templates;
    }

    public void setTemplates(AuthorizationTemplates templates) {
        this.templates = templates;
    }

    public static void main(String[] args) {
        /*
        This will create an example access token config entry with templates.
         */
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

    @Override
    public String getType() {
        if(type == null){
           type =  AT_DEFAULT_HANDLER_TYPE;
        }
        return type;
    }
}
