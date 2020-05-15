package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;

/**
 * Constants for RFC 8693: The token exchange endpoint
 * <p>Created by Jeff Gaynor<br>
 * on 9/26/17 at  3:20 PM
 */
public interface RFC8693Constants extends OA2Constants {
    String IETF_CAPUT = "urn:ietf:params:"; // Should never change.
    String GRANT_TYPE_TOKEN_EXCHANGE = IETF_CAPUT + "grant_type:token_exchange";
    String ACCESS_TOKEN_TYPE = IETF_CAPUT + "token_type:access_token";
    String REFRESH_TOKEN_TYPE = IETF_CAPUT + "token_type:refresh_token";
    String ID_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:id_token";
    //Indicates that the token is a base64url-encoded SAML 1.1
    String SAML1_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:saml1";
    //Indicates that the token is a base64url-encoded SAML 2.0
    String SAML2_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:saml2";
    // This is tricky since it means that the requested type is specifically a JWT
    String JWT_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:jwt";
    String ISSUED_TOKEN_TYPE = "issued_token_type";
    String ACTOR_TOKEN = "actor_token";
    String ACTOR_TOKEN_TYPE = "actor_token_type";
    String SUBJECT_TOKEN = "subject_token";
    String SUBJECT_TOKEN_TYPE = "subject_token_type";
    String AUDIENCE = "audience";
    String RESOURCE = "resource";
    String TOKEN_TYPE_BEARER = "Bearer"; //as per RFC 6750
    String TOKEN_TYPE_MAC = "MAC"; //as per RFC 6750
}