package edu.uiuc.ncsa.oa4mp.delegation.oa2;

/**
 * These are the standard tags as per section 3 of https://openid.net/specs/openid-connect-discovery-1_0.html
 * <p>Created by Jeff Gaynor<br>
 * on 12/13/23 at  11:44 AM
 */
public interface OIDCDiscoveryTags {
     String TOKEN_ENDPOINT = "token_endpoint";
     String USERINFO_ENDPOINT = "userinfo_endpoint";
     String TOKEN_INTROSPECTION_ENDPOINT = "introspection_endpoint";
     String TOKEN_REVOCATION_ENDPOINT = "revocation_endpoint";
     String RESPONSE_MODES_SUPPORTED = "response_modes_supported";
     String TOKEN_REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED = "revocation_endpoint_auth_methods_supported";
     String ISSUER = "issuer";
     String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization_endpoint";
     String OPENID_CONFIG_PATH = "openid-configuration";
     String OAUTH_AUTHZ_SERVER_PATH = "oauth-authorization-server";
     String WELL_KNOWN_PATH = ".well-known";
     String CODE_CHALLENGE_METHOD_SUPPORTED = "code_challenge_method_supported"; // RFC 7636
    String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    String REGISTRATION_ENDPOINT = "registration_endpoint";

    String JWKS_URI = "jwks_uri";
    String JWKS_CERTS = "certs";
    String AUTHORIZATION_ENDPOINT_DEFAULT = "authorize";
    String DEVICE_AUTHORIZATION_ENDPOINT_DEFAULT = "device_authorization";
    String TOKEN_ENDPOINT_DEFAULT = "token";
    String USER_INFO_ENDPOINT_DEFAULT = "userinfo";
    String INTROSPECTION_ENDPOINT_DEFAULT = "introspect";
    String REVOCATION_ENDPOINT_DEFAULT = "revoke";

}
