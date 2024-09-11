package org.oa4mp.delegation.server.server;

import org.oa4mp.delegation.server.OA2Constants;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/24/20 at  11:43 AM
 */
// Has to be placed in this package since it used by both client and server code.
    
public interface  RFC8693Constants extends OA2Constants {
    String IETF_CAPUT = "urn:ietf:params:"; // Should never change.
    String GRANT_TYPE_TOKEN_EXCHANGE = IETF_CAPUT + "oauth:grant-type:token-exchange"; // Note. The. Damn. Hyphens.
    String ACCESS_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:access_token"; // Note. The. Damn. Underscores.
    String REFRESH_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:refresh_token";
    String ID_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:id_token";
    //Indicates that the token is a base64url-encoded SAML 1.1
    String SAML1_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:saml1";
    //Indicates that the token is a base64url-encoded SAML 2.0
    String SAML2_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:saml2";
    // This is tricky since it means that the requested type is specifically a JWT ==> https://tools.ietf.org/html/rfc7523
    String JWT_TOKEN_TYPE = IETF_CAPUT + "oauth:token-type:jwt";
    String ISSUED_TOKEN_TYPE = "issued_token_type";
    String ACTOR_TOKEN = "actor_token";
    String ACTOR_TOKEN_TYPE = "actor_token_type";
    String REQUESTED_TOKEN_TYPE = "requested_token_type";
    String SUBJECT_TOKEN = "subject_token";
    String SUBJECT_TOKEN_TYPE = "subject_token_type";
    String AUDIENCE = "audience";
    String RESOURCE = "resource";
    String TOKEN_TYPE_BEARER = "Bearer"; //as per RFC 6750
    String TOKEN_TYPE_MAC = "MAC"; //as per RFC 6750
    String TOKEN_TYPE_N_A = "N_A"; //as per RFC 6750, used when the tokencannot be a bearer or other token (e.g. refresh token).
}
