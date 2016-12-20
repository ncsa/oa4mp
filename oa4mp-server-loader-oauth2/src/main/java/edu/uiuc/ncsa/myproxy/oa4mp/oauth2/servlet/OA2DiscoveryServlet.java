package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.DiscoveryServlet;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/12/16 at  1:18 PM
 */
public class OA2DiscoveryServlet extends DiscoveryServlet {

    @Override
    protected JSONObject setValues(JSONObject jsonObject) {
        JSONObject json =  super.setValues(jsonObject);
        json.put("token_endpoint",null);
        json.put( "token_endpoint_auth_methods_supported",null);
        json.put("issuer","varies");
        json.put( "token_endpoint_auth_signing_alg_values_supported",null);
        json.put("userinfo_endpoint","userInfo");
        JSONArray scopes = new JSONArray();
        Collection<String> serverScopes = ((OA2SE)getServiceEnvironment()).getScopes();
        for(String s: serverScopes){
            scopes.add(s);
        }

        json.put("scopes_supported",scopes);
        json.put("response_types_supported",null);
        json.put("subject_types_supported",null);
        JSONArray signingAlgs = new JSONArray();
        signingAlgs.add("RS256");
        signingAlgs.add("ES256");
        signingAlgs.add("HS256");
        json.put("id_token_signing_alg_values_supported",signingAlgs);

        return json;
    }
    /*
     /*
     {
   "userinfo_signing_alg_values_supported":
     ["RS256", "ES256", "HS256"],
   "userinfo_encryption_alg_values_supported":
     ["RSA1_5", "A128KW"],
   "userinfo_encryption_enc_values_supported":
     ["A128CBC-HS256", "A128GCM"],
   ,
   "id_token_encryption_alg_values_supported":
     ["RSA1_5", "A128KW"],
   "id_token_encryption_enc_values_supported":
     ["A128CBC-HS256", "A128GCM"],
   "request_object_signing_alg_values_supported":
     ["none", "RS256", "ES256"],
   "display_values_supported":
     ["page", "popup"],
   "claim_types_supported":
     ["normal", "distributed"],
   "claims_supported":
     ["sub", "iss", "auth_time", "acr",
      "name", "given_name", "family_name", "nickname",
      "profile", "picture", "website",
      "email", "email_verified", "locale", "zoneinfo",
      "http://example.info/claims/groups"],
   "claims_parameter_supported":
     true,
   "service_documentation":
     "http://server.example.com/connect/service_documentation.html",
   "ui_locales_supported":
     ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
  }

     */
}
