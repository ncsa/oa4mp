package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/6/18 at  9:54 AM
 */
public interface OIDCCMConstants {
    /**
     * <b>REQUIRED</b>. Array of Redirection URI values used by the Client. One of these registered Redirection URI values MUST exactly match the redirect_uri parameter value used in each Authorization Request, with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
     */
    public static final String REDIRECT_URIS = "redirect_uris";
    /**
     * <b>OPTIONAL</b>. JSON array containing a list of the OAuth 2.0 response_type values that the
     * Client is declaring that it will restrict itself to using. If omitted, the default is that the Client
     * will use only the code Response Type.
     * <br/><br/>
     * See also <a href="https://tools.ietf.org/html/rfc7591#section-2.1">the spec</a>.
     */

    /*
     Note from me to Terry that finally summarized this
     ---
     You cited the OIDC spec and my point is that we are no longer requiring all clients to be OIDC.
     I refer to https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660 aka
     "code flows summary" Here is my understanding:

     OIDC = openid scope
     response_type = ["code"]   ==> authorization code flow,  id token returned from token endpoint.
     response_type=["id_token"] ==> implicit flow, no token endpoint, id token returned from authorization end point
     
     Non-OIDC = no openid scope
     response_type=["code"] ==> authorization code flow, no id token, section 1 code flows summary
     response_type=["code", "id_token"]  ==> authorization code flow, requests an id token from the token endpoint, section 5 code flows summary
     response_type=["id_token",...] means implicit flow, id_token issed at authorization endpoint, Section 3 code flows summary.

     */
    public static final String RESPONSE_TYPES = "response_types";
    /**
     * <b>OPTIONAL</b>. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring that it will restrict itself to using. The Grant Type values used by OpenID Connect are:
     * <ul>
     * <li><b>authorization_code</b>: The Authorization Code Grant Type described in OAuth 2.0 Section 4.1.</li>
     * <li><b>implicit</b>: The Implicit Grant Type described in OAuth 2.0 Section 4.2.</li>
     * <li><b>refresh_token</b>: The Refresh Token Grant Type described in OAuth 2.0 Section 6.</li>
     * </ul>
     * <p>
     * Refresh token  only modifies the behavior of authorization_code.
     * It has no meaning by itself.
     * </p>
     * <p>
     * The following table encapsulates this <a href="https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660">summary</a>
     * for the correspondence between response_type values that the client will
     * use and grant_type values that MUST be included in the registered grant_types list:
     * <p>
     *
     * <table style="width:100%">
     * <tr>
     * <th>response_type</th>
     * <th>grant_type</th>
     * <th>end point</th>
     * <th>Note</th>
     * </tr>
     * <tr>
     * <td>code</td>
     * <td>authorization_code</td>
     * <td>authz, token</td>
     * <td>openid scope present = issue id token. Otherwise, no id token</td>
     * </tr>
     * <tr>
     * <td>token</td>
     * <td>implicit</td>
     * <td>authz only</td>
     * <td>only access token issued, never id token.</td>
     * </tr>
     * <tr>
     * <td>id_token</td>
     * <td>implicit</td>
     * <td>authz only</td>
     * <td>issue an id token.</td>
     * </tr>
     * <tr>
     * <td>token  id_token</td>
     * <td>implicit</td>
     * <td>authz only</td>
     * <td>both an access token and an id token are issued. <b>NOTE</b>
     * this also means the <a href="http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken">at_hash</a> must be
     * calculated and embedded in the id token!</td>
     * </tr>
     * <tr>
     * <td>code  id_token</td>
     * <td>authorization_code, implicit</td>
     * <td>authz, token</td>
     * <td>Both an access token and an id token are issued rom the token endpoint. The authz endpoint issues an id token
     * as well and these two id tokens <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2">are not the same!</a>
     * In particular, the id token from the authz endpoint has a <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken">hash of the code</a>
     * vs. a hash of the access token when issued from the token endpoint. </td>
     * </tr>
     * <tr>
     * <td>code  token</td>
     * <td>authorization_code, implicit</td>
     * <td>authz, token</td>
     * <td>Each endpoint returns an access token. The one from the authz endpoint is bound by
     * <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridAccessToken2">this requirement</a>.
     * Additionally, only if the scope is openid  does the token endpoint return an id_token.</td>
     * </tr>
     * <tr>
     * <td>code token id_token</td>
     * <td>authorization_code, implicit</td>
     * <td>authz, token</td>
     * <td>access tokens issued from both endpoints, as are id tokens. As expected, hashes of the respective token or code
     * are embedded as per <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridAccessToken2">access tokens</a>
     * and <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken">id tokens</a>.</td>
     * </tr>
     * <tr>
     * <td>none</td>
     * <td>authorization_code, implicit</td>
     * <td>authz only</td>
     * <td>Nothing is returned. This basically just returns a succesful response if the user could log in, but nothing else.</td>
     * </tr>
     * </table>
     * <p>
     * If omitted, the default is that the Client will use only the authorization_code Grant Type.
     * <br/>
     * See <a href="https://tools.ietf.org/html/rfc7591#section-2.1">the spec</a>.
     * <pre>
     * +-----------------------------------------------+-------------------+
     * | grant_types value includes:                   | response_types    |
     * |                                               | value includes:   |
     * +-----------------------------------------------+-------------------+
     * | authorization_code                            | code              |
     * | implicit                                      | token             |
     * | password                                      | (none)            |
     * | client_credentials                            | (none)            |
     * | refresh_token                                 | (none)            |
     * | urn:ietf:params:oauth:grant-type:jwt-bearer   | (none)            |
     * | urn:ietf:params:oauth:grant-type:saml2-bearer | (none)            |
     * +-----------------------------------------------+-------------------+
     * </pre>
     *
     * </p>
     */
    public static final String GRANT_TYPES = "grant_types";


    /**
     * <b>OPTIONAL</b>. Kind of the application. The default, if omitted, is web. The defined values are native or web.
     * Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
     * they MUST NOT use localhost as the hostname. Native Clients MUST only register redirect_uris using custom URI
     * schemes or URLs using the http: scheme with localhost as the hostname. Authorization Servers MAY place
     * additional constraints on Native Clients. Authorization Servers MAY reject Redirection URI values using the
     * http scheme, other than the localhost case for Native Clients. The Authorization Server MUST verify that all
     * the registered redirect_uris conform to these constraints. This prevents sharing a Client ID across different
     * types of Clients.
     */
    public static final String APPLICATION_TYPE = "application_type";
    /**
     * <b>OPTIONAL</b>. Array of e-mail addresses of people responsible for this Client. This might be used by some
     * providers to enable a Web user interface to modify the Client information.
     */
    public static final String CONTACTS = "contacts";


    /**
     * <b>OPTIONAL</b>. Name of the Client to be presented to the End-User. If desired, representation of this Claim
     * in different languages and scripts is represented as described in Section 2.1.
     */
    public static final String CLIENT_NAME = "client_name";

    /**
     * <b>OPTIONAL</b>. URL that references a logo for the Client application. If present, the server SHOULD
     * display this image to the End-User during approval. The value of this field MUST point to a valid image file.
     * If desired, representation of this Claim in different languages and scripts is represented as described in
     * Section 2.1.
     */
    public static final String LOGO_URI = "logo_uri";

    /**
     * <b>OPTIONAL</b>. URL of the home page of the Client. The value of this field MUST point to a valid Web page.
     * If present, the server SHOULD display this URL to the End-User in a followable fashion. If desired,
     * representation of this Claim in different languages and scripts is represented as described in Section 2.1.
     */
    public static final String CLIENT_URI = "client_uri";

    /**
     * <b>OPTIONAL</b>. URL that the Relying Party Client provides to the End-User to read about the how the profile
     * data will be used. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display
     * this URL to the End-User if it is given. If desired, representation of this Claim in different languages and
     * scripts is represented as described in Section 2.1.
     */
    public static final String POLICY_URI = "policy_uri";

    /**
     * <b>OPTIONAL</b>. URL that the Relying Party Client provides to the End-User to read about the Relying Party's
     * terms of service. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display
     * this URL to the End-User if it is given. If desired, representation of this Claim in different languages and
     * scripts is represented as described in Section 2.1.
     */
    public static final String TOS_URI = "tos_uri";

    /**
     * <b>OPTIONAL</b>. URL for the Client's JSON Web Key Set [JWK] document. If the Client signs requests to the
     * Server, it contains the signing key(s) the Server uses to validate signatures from the Client.
     * The JWK Set MAY also contain the Client's encryption keys(s), which are used by the Server to encrypt
     * responses to the Client. When both signing and encryption keys are made available, a use (Key Use)
     * parameter value is <b>REQUIRED</b> for all keys in the referenced JWK Set to indicate each key's intended
     * usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so is
     * NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of
     * keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
     */
    public static final String JWKS_URI = "jwks_uri";

    /**
     * <b>OPTIONAL</b>. Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the jwks parameter
     * are the same as the jwks_uri parameter, other than that the JWK Set is passed by value, rather than by reference
     * . This parameter is intended only to be used by Clients that, for some reason, are unable to use the jwks_uri
     * parameter, for instance, by native applications that might not have a location to host the contents of the JWK
     * Set. If a Client can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that it does not
     * enable key rotation (which jwks_uri does, as described in Section 10 of OpenID Connect Core 1.0 [OpenID.Core]).
     * The jwks_uri and jwks parameters MUST NOT be used together.
     */
    public static final String JWKS = "jwks";

    /**
     * <b>OPTIONAL</b>. URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The
     * URL references a file with a single JSON array of redirect_uri values. Please see Section 5. Providers that use
     * pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value provided in the Subject Identifier
     * calculation for pairwise identifiers.
     */
    public static final String SECTOR_IDENTIFIER_URI = "sector_identifier_uri";

    /**
     * <b>OPTIONAL</b>. subject_type requested for responses to this Client. The subject_types_supported Discovery
     * parameter contains a list of the supported subject_type values for this server. Valid types include pairwise
     * and public.
     */
    public static final String SUBJECT_TYPE = "subject_type";

    /**
     * <b>OPTIONAL</b>. JWS alg algorithm [JWA] <b>REQUIRED</b> for signing the ID Token issued to this Client. The
     * value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types that return no
     * ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if
     * omitted, is RS256. The public key for validating the signature is provided by retrieving the JWK Set referenced
     * by the jwks_uri element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
     */
    public static final String ID_TOKEN_SIGNED_RESPONSE_ALG = "id_token_signed_response_alg";

    /**
     * <b>OPTIONAL</b>. JWE alg algorithm [JWA] <b>REQUIRED</b> for encrypting the ID Token issued to this Client. If
     * this is requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined
     * in [JWT]. The default, if omitted, is that no encryption is performed.
     */
    public static final String ID_TOKEN_ENCRYPTED_RESPONSE_ALG = "id_token_encrypted_response_alg";

    /**
     * <b>OPTIONAL</b>. JWE enc algorithm [JWA] <b>REQUIRED</b> for encrypting the ID Token issued to this Client.
     * If id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
     * When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
     */
    public static final String ID_TOKEN_ENCRYPTED_RESPONSE_ENC = "id_token_encrypted_response_enc";

    /**
     * <b>OPTIONAL</b>. JWS alg algorithm [JWA] <b>REQUIRED</b> for signing UserInfo Responses.
     * If this is specified, the response will be JWT [JWT] serialized, and signed using JWS. The default, if omitted,
     * is for the UserInfo Response to return the Claims as a UTF-8 encoded JSON object using
     * the application/json content-type.
     */
    public static final String USERINFO_SIGNED_RESPONSE_ALG = "userinfo_signed_response_alg";

    /**
     * <b>OPTIONAL</b>. JWE [JWE] alg algorithm [JWA] <b>REQUIRED</b> for encrypting UserInfo Responses.
     * If both signing and encryption are requested, the response will be signed then encrypted, with the result
     * being a Nested JWT, as defined in [JWT]. The default, if omitted, is that no encryption is performed.
     */
    public static final String USERINFO_ENCRYPTED_RESPONSE_ALG = "userinfo_encrypted_response_alg";

    /**
     * <b>OPTIONAL</b>. JWE enc algorithm [JWA] <b>REQUIRED</b> for encrypting UserInfo Responses.
     * If userinfo_encrypted_response_alg is specified, the default for this value is A128CBC-HS256.
     * When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
     */
    public static final String USERINFO_ENCRYPTED_RESPONSE_ENC = "userinfo_encrypted_response_enc";

    /**
     * <b>OPTIONAL</b>. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP.
     * All Request Objects from this Client MUST be rejected, if not signed with this algorithm. Request Objects
     * are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST be used both when
     * the Request Object is passed by value (using the request parameter) and when it is passed by reference
     * (using the request_uri parameter). Servers SHOULD support RS256. The value none MAY be used. The default,
     * if omitted, is that any algorithm supported by the OP and the RP MAY be used.
     */
    public static final String REQUEST_OBJECT_SIGNING_ALG = "request_object_signing_alg";

    /**
     * <b>OPTIONAL</b>. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for
     * encrypting Request Objects sent to the OP. This parameter SHOULD be included when symmetric
     * encryption will be used, since this signals to the OP that a client_secret value needs to be returned
     * from which the symmetric key will be derived, that might not otherwise be returned. The RP MAY still use other
     * supported encryption algorithms or send unencrypted Request Objects, even when this parameter is present.
     * If both signing and encryption are requested, the Request Object will be signed then encrypted, with the result
     * being a Nested JWT, as defined in [JWT]. The default, if omitted, is that the RP is not declaring whether it
     * might encrypt any Request Objects.
     */
    public static final String REQUEST_OBJECT_ENCRYPTION_ALG = "request_object_encryption_alg";

    /**
     * <b>OPTIONAL</b>. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to the OP. If request_object_encryption_alg is specified, the default for this value is A128CBC-HS256. When request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided.
     */
    public static final String REQUEST_OBJECT_ENCRYPTION_ENC = "request_object_encryption_enc";

    /**
     * <b>OPTIONAL</b>. Requested Client Authentication method for the Token Endpoint.
     * The options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt,
     * and none, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication
     * methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the
     * HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
     */
    public static final String TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";

    /**
     * <b>OPTIONAL</b>. JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to
     * authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication
     * methods. All Token Requests using these authentication methods from this Client MUST be rejected, if the
     * JWT is not signed with this algorithm. Servers SHOULD support RS256. The value none MUST NOT be used.
     * The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
     */
    public static final String TOKEN_ENDPOINT_AUTH_SIGNING_ALG = "token_endpoint_auth_signing_alg";

    /**
     * <b>OPTIONAL</b>. Default Maximum Authentication Age. Specifies that the End-User MUST be actively authenticated
     * if the End-User was authenticated longer ago than the specified number of seconds. The max_age request
     * parameter overrides this default value. If omitted, no default Maximum Authentication Age is specified.
     */
    public static final String DEFAULT_MAX_AGE = "default_max_age";

    /**
     * <b>OPTIONAL</b>. Boolean value specifying whether the auth_time Claim in the ID Token is <b>REQUIRED</b>.
     * It is <b>REQUIRED</b> when the value is true. (If this is false, the auth_time Claim can still be dynamically
     * requested as an individual Claim for the ID Token using the claims request parameter described in Section 5.5.1
     * of OpenID Connect Core 1.0 [OpenID.Core].) If omitted, the default value is false.
     */
    public static final String REQUIRE_AUTH_TIME = "require_auth_time";

    /**
     * <b>OPTIONAL</b>. Default requested Authentication Context Class Reference values. Array of strings that specifies the default acr values that the OP is being requested to use for processing requests from this Client, with the values appearing in order of preference. The Authentication Context Class satisfied by the authentication performed is returned as the acr Claim Value in the issued ID Token. The acr Claim is requested as a Voluntary Claim by this parameter. The acr_values_supported discovery element contains a list of the supported acr values supported by this server. Values specified in the acr_values request parameter or an individual acr Claim request override these default values.
     */
    public static final String DEFAULT_ACR_VALUES = "default_acr_values";

    /**
     * <b>OPTIONAL</b>. URI using the https scheme that a third party can use to initiate a login by the RP, as specified in Section 4 of OpenID Connect Core 1.0 [OpenID.Core]. The URI MUST accept requests via both GET and POST. The Client MUST understand the login_hint and iss parameters and SHOULD support the target_link_uri parameter.
     */
    public static final String INITIATE_LOGIN_URI = "initiate_login_uri";

    /**
     * <b>OPTIONAL</b>. Array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY cache the contents of the files referenced by these URIs and not retrieve them at the time they are used in a request. OPs can require that request_uri values used be pre-registered with the require_request_uri_registration discovery parameter.
     * If the contents of the request file could ever change, these URI values SHOULD include the base64url encoded SHA-256 hash value of the file contents referenced by the URI as the value of the URI fragment. If the fragment value used for a URI changes, that signals the server that its cached value for that URI with the old fragment value is no longer valid.
     */
    public static final String REQUEST_URIS = "request_uris";

    // The following are used in responses.

    /**
     * <b>REQUIRED</b>. Unique Client Identifier. It MUST NOT be currently valid for any other registered Client.
     */

    public static final String CLIENT_ID = "client_id";
    /**
     * <b>OPTIONAL</b>. Client Secret. The same Client Secret value MUST NOT be assigned to multiple Clients. This value is
     * used by Confidential Clients to authenticate to the Token Endpoint, as described in Section 2.3.1 of OAuth 2.0,
     * and for the derivation of symmetric encryption key values, as described in Section 10.2 of
     * OpenID Connect Core 1.0 [OpenID.Core]. It is not needed for Clients selecting a token_endpoint_auth_method of
     * private_key_jwt unless symmetric encryption will be used.
     */
    public static final String CLIENT_SECRET = "client_secret";
    /**
     * <b>OPTIONAL</b>. Registration Access Token that can be used at the Client Configuration Endpoint to perform subsequent
     * operations upon the Client registration.
     */
    public static final String REGISTRATION_ACCESS_TOKEN = "registration_access_token";
    /**
     * <b>OPTIONAL</b>. Location of the Client Configuration Endpoint where the Registration Access Token can be used to
     * perform subsequent operations upon the resulting Client registration. Implementations MUST either return both
     * a Client Configuration Endpoint and a Registration Access Token or neither of them.
     */
    public static final String REGISTRATION_CLIENT_URI = "registration_client_uri";
    /**
     * <b>OPTIONAL</b>. Time at which the Client Identifier was issued. Its value is a JSON number representing the number
     * of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
     */
    public static final String CLIENT_ID_ISSUED_AT = "client_id_issued_at";
    /**
     * <b>REQUIRED</b> if client_secret is issued. Time at which the client_secret will expire or 0 if it will not expire.
     * Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured
     * in UTC until the date/time.
     */
    public static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";

}
