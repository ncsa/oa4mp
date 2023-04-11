package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.DiscoveryServlet;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Scopes;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7636Util;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/12/16 at  1:18 PM
 */
/*
   Canonical example: https://accounts.google.com/.well-known/openid-configuration
 */
public class OA2DiscoveryServlet extends DiscoveryServlet {

    public static final String TOKEN_ENDPOINT = "token_endpoint";
    public static final String USERINFO_ENDPOINT = "userinfo_endpoint";
    public static final String TOKEN_INTROSPECTION_ENDPOINT = "introspection_endpoint";
    public static final String TOKEN_REVOCATION_ENDPOINT = "revocation_endpoint";
    public static final String RESPONSE_MODES_SUPPORTED = "response_modes_supported";
    public static final String TOKEN_REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED = "revocation_endpoint_auth_methods_supported";
    public static final String ISSUER = "issuer";
    public static final String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization_endpoint";
    public static final String OPENID_CONFIG_PATH = "openid-configuration";
    public static final String OAUTH_AUTHZ_SERVER_PATH = "oauth-authorization-server";
    public static final String WELL_KNOWN_PATH = ".well-known";
    public static final String CODE_CHALLENGE_METHOD_SUPPORTED = "code_challenge_method_supported"; // RFC 7636
    public static final String CERTS = "/certs";

    public static String DISCOVERY_PATH_SEPARATOR = "/";

    protected VirtualOrganization getVO(HttpServletRequest req, String requestUri) {
        VirtualOrganization vo = null;
        String host = getOA2SE().getServiceAddress().getHost();
        String p = requestUri.substring(getOA2SE().getServiceAddress().getPath().length());
        StringTokenizer st = new StringTokenizer(p, "/");
        // Check the format
        String x = st.nextToken();
        // Case 1 , this starts out as ../.well-known so check what comes next
        if (x.equals(WELL_KNOWN_PATH)) {
            if (!st.hasMoreTokens()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "unsupported discovery url",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            String x1 = st.nextToken();
            if (x1.equals(OPENID_CONFIG_PATH) || x1.equals(OAUTH_AUTHZ_SERVER_PATH)) {
                if (st.hasMoreTokens()) {
                    String component = st.nextToken();
                    // Fix for CIL-976
                    vo = getOA2SE().getVOStore().findByPath(host + DISCOVERY_PATH_SEPARATOR + component);
                    if (vo == null) {
                        // Then this is not recognized.
                        throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                                "unknown virtual organization \"" + component + "\"",
                                HttpStatus.SC_BAD_REQUEST,
                                null);
                    }
                    return vo;
                } else {
                    return vo; // no extra component, so return null = default
                }
            }
        }
        // getOA2SE().getAdminClientStore();
        if (!st.hasMoreTokens()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "unsupported discovery url",
                    HttpStatus.SC_BAD_REQUEST,
                    null);

        }
        // case 2: Check for default
        String nextToken = st.nextToken();
        if (x.equals(WELL_KNOWN_PATH) && nextToken.equals(OPENID_CONFIG_PATH) || nextToken.equals(OAUTH_AUTHZ_SERVER_PATH)) {
            return vo; // default case, no vo components.
        }
        // case 3, vo component comes first
        if (nextToken.equals(WELL_KNOWN_PATH) && st.nextToken().equals(OPENID_CONFIG_PATH) && !st.hasMoreTokens()) {
            // Fix for CIL-976
            vo = getOA2SE().getVOStore().findByPath(host + DISCOVERY_PATH_SEPARATOR + x);
        } else {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "unsupported discovery url for \"" + x + "\"",
                    HttpStatus.SC_BAD_REQUEST,
                    null);

        }
        // default case, no special component, so return default vo.
        return vo;
    }

    protected OA2SE getOA2SE() {
        return (OA2SE) getServiceEnvironment();
    }

    /*
    With a component
    https://cilogon.org/fnal/.well-known/openid-configuration   <-- OIDC Discovery 1. Can't support this in Apache + Tomcat config.
    https://cilogon.org/.well-known/openid-configuration/fnal
    https://cilogon.org/.well-known/oauth-authorization-server/fnal

    versus no component

    https://cilogon.org/.well-known/openid-configuration
    https://cilogon.org/.well-known/oauth-authorization-server

     */
    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        //     ServletDebugUtil.printAllParameters(this.getClass(), httpServletRequest);

        String requestUri = httpServletRequest.getRequestURI();
        boolean isCerts = false;
        if (requestUri.contains(CERTS)) {
            isCerts = true;
            if (requestUri.endsWith(CERTS)) {
                requestUri = requestUri.substring(0, requestUri.length() - CERTS.length()); // whack off certs part
            } else {
                requestUri = requestUri.substring(requestUri.indexOf(CERTS) + CERTS.length()); // whack off leading certs part (vo suffix case)
            }
        }
        // normalize the uri
        if (isCerts) {
            String discoveryPath = requestUri.substring(1 + requestUri.lastIndexOf("/"));
            // Fix for CIL-976
            VirtualOrganization vo = getOA2SE().getVOStore().findByPath(getOA2SE().getServiceAddress().getHost() + DISCOVERY_PATH_SEPARATOR + discoveryPath);
            JSONWebKeys publicKeys;
            if (vo == null) {
                publicKeys = JSONWebKeyUtil.makePublic(((OA2SE) getServiceEnvironment()).getJsonWebKeys());
            } else {
                publicKeys = JSONWebKeyUtil.makePublic(vo.getJsonWebKeys());
            }
            JSONObject json = JSONWebKeyUtil.toJSON(publicKeys);
            String out = JSONUtils.valueToString(json, 1, 0);

            httpServletResponse.setHeader("Content-Type", "application/json;charset=UTF-8");

            PrintWriter printWriter = httpServletResponse.getWriter();
            printWriter.write(out);
            printWriter.flush();
            printWriter.close();
            return;


        }

        VirtualOrganization vo = getVO(httpServletRequest, requestUri);
/*
        if (requestUri.endsWith("/")) {
            requestUri = requestUri.substring(0, requestUri.length() - 1);
        }*/
        // Next bit is very basic -- just call setValues in this class which does all the work.
        //super.doIt(httpServletRequest, httpServletResponse);
        JSONObject jsonObject = new JSONObject();
        jsonObject = setValues(httpServletRequest, jsonObject, vo);
        String out = JSONUtils.valueToString(jsonObject, 1, 0);
        httpServletResponse.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter printWriter = httpServletResponse.getWriter();
        printWriter.write(out);
        printWriter.close();
        printWriter.flush();
    }

    public static String getIssuer(HttpServletRequest request) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        if (oa2SE.getIssuer() != null) {
            return oa2SE.getIssuer();
        } else {
            return getRequestURI(request, false); // default --  use server + path
        }
    }

    protected JSONObject setValues(HttpServletRequest request, JSONObject jsonObject, VirtualOrganization vo) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        String requestURI = getRequestURI(request);
        if (requestURI.endsWith("/")) {
            requestURI = requestURI.substring(0, requestURI.length() - 1); // shave off trailing slash
        }
        JSONObject json = super.setValues(request, jsonObject);
        if (vo == null) {
            json.put("jwks_uri", requestURI + "/certs");
        } else {
            // has to go at the end since there is no way Tomcat can have it specified otherwise
            // without a lot of gyrations in the web.xml file.
            String p = vo.getDiscoveryPath().substring(vo.getDiscoveryPath().lastIndexOf("/") + 1);
            json.put("jwks_uri", requestURI + "/certs" + "/" + p);

        }
        if (vo == null) {
            json.put(ISSUER, getIssuer(request));
        } else {
            json.put(ISSUER, vo.getIssuer());
        }
        json.put(TOKEN_ENDPOINT, requestURI + "/token"); // spec
        json.put(USERINFO_ENDPOINT, requestURI + "/userinfo"); // spec
        //CIL-738 fix
        json.put(TOKEN_INTROSPECTION_ENDPOINT, requestURI + "/introspect"); //spec
        json.put(TOKEN_REVOCATION_ENDPOINT, requestURI + "/revoke"); //spec
        JSONArray revAuthMethods = new JSONArray();
        revAuthMethods.add("client_secret_basic");
        json.put(TOKEN_REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED, revAuthMethods);

        if (oa2SE.isRfc8628Enabled()) {
            json.put(DEVICE_AUTHORIZATION_ENDPOINT, oa2SE.getRfc8628ServletConfig().deviceAuthorizationEndpoint);
        }

        json.put("token_endpoint_auth_methods_supported", null);

        JSONArray tokenEndpointAuthSupported = new JSONArray();
        tokenEndpointAuthSupported.add("client_secret_post");
        tokenEndpointAuthSupported.add("client_secret_basic");
        json.put("token_endpoint_auth_methods_supported", tokenEndpointAuthSupported);
        JSONArray subjectTypes = new JSONArray();
        subjectTypes.add("public");
        json.put("subject_types_supported", subjectTypes);
        JSONArray scopes = new JSONArray();
        Collection<String> serverScopes = oa2SE.getScopes();
        for (String s : serverScopes) {
            scopes.add(s);
        }
        if (!scopes.contains(OA2Scopes.SCOPE_OFFLINE_ACCESS)) {
            scopes.add(OA2Scopes.SCOPE_OFFLINE_ACCESS);
        }

        JSONArray ccm = new JSONArray();
        ccm.add(RFC7636Util.METHOD_PLAIN);
        ccm.add(RFC7636Util.METHOD_S256);
        json.put(CODE_CHALLENGE_METHOD_SUPPORTED, ccm);
        json.put("scopes_supported", scopes);
        JSONArray responseTypes = new JSONArray();
        responseTypes.add("code");
        //   responseTypes.add("token");
        responseTypes.add("id_token");
        json.put("response_types_supported", responseTypes);

        JSONArray grantTypes = new JSONArray();
        // CIL-1312
        grantTypes.add("web");
        grantTypes.add(OA2Constants.GRANT_TYPE_TOKEN_INFO);
        if (oa2SE.isRfc8693Enabled()) {
            grantTypes.add(RFC8693Constants.GRANT_TYPE_TOKEN_EXCHANGE);
        }

        grantTypes.add(OA2Constants.GRANT_TYPE_REFRESH_TOKEN);
        grantTypes.add(OA2Constants.GRANT_TYPE_AUTHORIZATION_CODE);
        if (oa2SE.isRfc8628Enabled()) {
            grantTypes.add(RFC8628Constants2.GRANT_TYPE_DEVICE_CODE);
        }
        json.put("grant_types_supported", grantTypes);
        /*
        https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        talks about response modes and types, viz., response modes are optional
        and

           "The Response Type request parameter response_type informs the Authorization
            Server of the desired authorization processing flow, including what parameters
            are returned from the endpoints used. The Response Mode request parameter
            response_mode informs the Authorization Server of the mechanism to be
            used for returning Authorization Response parameters from the Authorization Endpoint.
            Each Response Type value also defines a default Response Mode mechanism to be used,
            if no Response Mode is specified using the request parameter."
         */
        JSONArray responseModesSupported = new JSONArray();
        responseModesSupported.add("query");
        responseModesSupported.add("fragment");
        responseModesSupported.add("form_post"); // https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        json.put(RESPONSE_MODES_SUPPORTED, responseModesSupported);

        JSONArray claimsSupported = new JSONArray();
        if (oa2SE.getClaimSource() != null) {
            claimsSupported.addAll(oa2SE.getClaimSource().getClaims());
            json.put("claims_supported", claimsSupported);
        }
        JSONArray signingAlgs = new JSONArray();
        signingAlgs.add("RS256");
        signingAlgs.add("RS384");
        signingAlgs.add("RS512");
        json.put("id_token_signing_alg_values_supported", signingAlgs);
        return json;
    }

}
