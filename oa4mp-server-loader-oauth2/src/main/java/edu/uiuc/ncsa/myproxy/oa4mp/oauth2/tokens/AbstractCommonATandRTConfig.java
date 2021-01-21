package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * These are the common configuration items for both access and refresh tokens, such
 * as lifetime, issuer etc.
 * <p>Created by Jeff Gaynor<br>
 * on 1/18/21 at  6:32 AM
 */
public class AbstractCommonATandRTConfig extends AbstractPayloadConfig {
    public static String SUBJECT_KEY = "subject";
    public static String ISSUER_KEY = "issuer";
    public static String AUDIENCE_KEY = "audience";
    public static String RESOURCE_KEY = "resource";

    String issuer;
    String subject;
    List<String> audience = new ArrayList<>();

    public List<URI> getResource() {
        return resource;
    }

    public void setResource(List<URI> resource) {
        this.resource = resource;
    }

    List<URI> resource = new ArrayList<>();

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


    /**
     * The list of audiences (i.e. returned in the {@link edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims#AUDIENCE}
     * claim) allowed
     * @return
     */
    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    @Override
      public void fromJSON(JSONObject jsonObject) {
          super.fromJSON(jsonObject);

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
        if (jsonObject.containsKey(RESOURCE_KEY)) {
            Object obj = jsonObject.get(RESOURCE_KEY);
            DebugUtil.trace(this, "Got resource=" + obj);
            // These are stored as strings in the JSON object os they are not munged
            resource = new ArrayList<>();
            List<String> raw = new ArrayList<>();
            if (obj instanceof JSONArray) {
                raw = (List<String>) obj;
            } else {
                ArrayList x = new ArrayList();
                x.add(obj.toString());
                raw = x;
            }
            for(String rr : raw){
                try {
                    resource.add(URI.create(rr));
                }catch(Throwable t){
                    // skip it.
                    DebugUtil.trace(this,"skipping bad resource: \"" + rr + "\":"  + t.getMessage());
                }
            }
        }


      }
    @Override
    public JSONObject toJSON() {
        JSONObject json = super.toJSON();
        if (issuer != null) {
            json.put(ISSUER_KEY, issuer);
        }

        if (subject != null) {
            json.put(SUBJECT_KEY, subject);
        }

        if (audience != null) {
            json.put(AUDIENCE_KEY, audience);
        }
        if(resource != null){
            // Convert to strings or these can get mangled by various JSON libraries.
            JSONArray j = new JSONArray();
            for(int i =0; i < resource.size(); i++){
                j.add(resource.get(i).toString());
            }
            json.put(AUDIENCE_KEY, j);

        }
        return json;
    }

}
