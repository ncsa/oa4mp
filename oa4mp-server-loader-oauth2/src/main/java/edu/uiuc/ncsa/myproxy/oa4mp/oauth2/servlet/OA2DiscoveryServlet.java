package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.DiscoveryServlet;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/12/16 at  1:18 PM
 */
public class OA2DiscoveryServlet extends DiscoveryServlet {

    public static final String TOKEN_ENDPOINT = "token_endpoint";
    public static final String USERINFO_ENDPOINT = "userinfo_endpoint";
    public static final String ISSUER = "issuer";

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        String requestUri = httpServletRequest.getRequestURI();
        // normalize the uri
        if (requestUri.endsWith("/")) {
            requestUri = requestUri.substring(0, requestUri.length() - 1);
        }
        if (requestUri.endsWith("/certs")) {
            JSONWebKeys publicKeys = JSONWebKeyUtil.makePublic(((OA2SE) getServiceEnvironment()).getJsonWebKeys());
            JSONObject json = JSONWebKeyUtil.toJSON(publicKeys);
            String out = JSONUtils.valueToString(json, 1, 0);

            httpServletResponse.setHeader("Content-Type", "application/json;charset=UTF-8");

            PrintWriter printWriter = httpServletResponse.getWriter();
            printWriter.write(out);
            printWriter.flush();
            printWriter.close();
            return;
        }
        super.doIt(httpServletRequest, httpServletResponse);
    }

    @Override
    protected JSONObject setValues(HttpServletRequest request, JSONObject jsonObject) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        String requestURI = getRequestURI(request);

        JSONObject json = super.setValues(request, jsonObject);
        json.put("jwks_uri", requestURI + "/certs");
        if(oa2SE.getServiceAddress()!=null) {
            json.put(ISSUER, oa2SE.getServiceAddress().getScheme() + "://" + oa2SE.getServiceAddress().getHost());
        }else{
            json.put(ISSUER, request.getScheme() + "://" + request.getServerName()); // default -- use server host name
        }
        json.put(TOKEN_ENDPOINT, requestURI + "/token");
        json.put(USERINFO_ENDPOINT, requestURI + "/userinfo");
        json.put("token_endpoint_auth_methods_supported", null);

        JSONArray tokenEndpointAuthSupported = new JSONArray();
        tokenEndpointAuthSupported.add("client_secret_post");
        json.put("token_endpoint_auth_methods_supported", tokenEndpointAuthSupported);
        JSONArray subjectTypes = new JSONArray();
        subjectTypes.add("public");
        json.put("subject_types_supported", subjectTypes);
        JSONArray scopes = new JSONArray();
        Collection<String> serverScopes = oa2SE.getScopes();
        for (String s : serverScopes) {
            scopes.add(s);
        }

        json.put("scopes_supported", scopes);
        JSONArray responseTypes = new JSONArray();
        responseTypes.add("code");
        responseTypes.add("token");
        responseTypes.add("id_token");
        json.put("response_types_supported", responseTypes);
        JSONArray claimsSupported = new JSONArray();
        if(oa2SE.getScopeHandler() != null){
            claimsSupported.addAll(oa2SE.getScopeHandler().getClaims());
            json.put("claims_supported", claimsSupported);
        }
        JSONArray signingAlgs = new JSONArray();
        signingAlgs.add("RS256");
        signingAlgs.add("RS384");
        signingAlgs.add("RS512");
        json.put("id_token_signing_alg_values_supported", signingAlgs);
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
