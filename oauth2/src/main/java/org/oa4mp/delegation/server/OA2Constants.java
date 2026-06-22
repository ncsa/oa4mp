package org.oa4mp.delegation.server;

/**
 * Constants that are used as e.g. parameters in client requests
 * <p>Created by Jeff Gaynor<br>
 * on 9/24/13 at  1:17 PM
 */
public interface OA2Constants {

     String ACCESS_TOKEN = "access_token";
     String ACCESS_TYPE = "access_type";

    /**
     * This is used for the code=grant token when getting the access
     * token. It looks like  {@link #RESPONSE_TYPE_CODE} (same value).
     * Use the right one in case something chages in the spec!
     */
     String AUTHORIZATION_CODE = "code";
     String AUTHORIZATION_STATE = "state";
     String REFRESH_LIFETIME = "rt_lifetime";
     String MAX_REFRESH_LIFETIME = "max_rt_lifetime";
     String ACCESS_TOKEN_LIFETIME = "at_lifetime";
     String MAX_ACCESS_TOKEN_LIFETIME = "max_at_lifetime";
     String STRICT_SCOPES = "strict_scopes";
     String USE_SERVER_SCOPES = "use_server_scopes";
     String DESCRIPTION = "description";
     String SKIP_SERVER_SCRIPTS = "skip_server_scripts";
     String CERT_LIFETIME = "certlifetime";
     String CERT_REQ = "certreq";
     String CLIENT_ID = "client_id";
     String CLIENT_SECRET = "client_secret";
     String DISPLAY = "display";
     String ERROR = "error";
     String ERROR_DESCRIPTION = "error_description";
     String ERROR_URI = "error_uri";
     String EXPIRES_IN = "expires_in";
    /**
     * Used as the parameter for the grant type, e.g. grant_type="authorization_code"
     */
     String GRANT_TYPE = "grant_type";
    /**
     * Use with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     */
     String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    /**
     * Use with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     */
     String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    /**
     * Use for <a href="https://tools.ietf.org/html/rfc6749#section-4.2">implicit flow.</a>
     */
     String GRANT_TYPE_IMPLICIT = "implicit";

    /**
     * Use for <a href="https://tools.ietf.org/html/rfc6749#section-4.4">client credentials flow.</a>
     */
    // https://github.com/ncsa/oa4mp/issues/209
     String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";

    // CIL-1101
     String GRANT_TYPE_DEVICE_FLOW = "urn:ietf:params:oauth:grant-type:device_code";

    // CIL-771 proposed grant type
    String GRANT_TYPE_TOKEN_INFO = "urn:oa4mp:params:oauth:grant-type:token-info";

     String NONCE = "nonce";
     String PROMPT = "prompt";
     String MAX_AGE = "max_age";
     String AUTH_GRANT_TOKEN_LIFETIME = "auth_grant_lifetime";
     String ID_TOKEN_HINT = "id_token_hint";
     String ID_TOKEN = "id_token";
     String ID_TOKEN_LIFETIME = "id_token_lifetime";
     String MAX_ID_TOKEN_LIFETIME = "max_id_token_lifetime";
     String ID_TOKEN_IDENTIFIER = "jti"; // was token_id
     String EA_SUPPORT = "ea_support";

     String REQUEST = "request";
     String REQUEST_URI = "request_uri";
     String AUTHORIZATION_TIME = "auth_time";

     String PROMPT_NONE = "none";
     String PROMPT_LOGIN = "login";
     String PROMPT_CONSENT = "consent";
     String PROMPT_SELECT_ACCOUNT = "select_account";
     String DISPLAY_PAGE = "page";
     String DISPLAY_POPUP = "popup";
     String DISPLAY_TOUCH = "touch";
     String DISPLAY_WAP = "wap";

     String REDIRECT_URI = "redirect_uri";
     String REFRESH_TOKEN = "refresh_token";
    /**
     * Used as the parameter to denote the response type, e.g. response_type="code"
     */
     String RESPONSE_TYPE = "response_type";

    /**
     * Used with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     */
     String RESPONSE_TYPE_CODE = "code";
    /**
     * Used with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     * <b>and</b> <a href="https://tools.ietf.org/html/rfc6749#section-4.2">implicit flow grant.</a>
     */
     String RESPONSE_TYPE_ID_TOKEN = "id_token";
    /**
     * Only used with <a href="https://tools.ietf.org/html/rfc6749#section-4.2">implicit flow grant.</a>
     */
     String RESPONSE_TYPE_TOKEN = "token";
    /**
     * Recently added
     */
     String RESPONSE_TYPE_NONE = "none";

     String STATE = "state";
     String SCOPE = "scope";
     String TOKEN_TYPE = "token_type";
     String BEARER_TOKEN_TYPE = "Bearer";
    /**
     * Use {@link #GRANT_TYPE_AUTHORIZATION_CODE}. Used to be only possible one but
     * we have more now...
     * @deprecated
     */
     String AUTHORIZATION_CODE_VALUE = "authorization_code";
    /**
     * as per <a href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes">the open id spec</a>
     */
     String RESPONSE_MODE = "response_mode";
     String RESPONSE_MODE_QUERY = "query";
     String RESPONSE_MODE_FRAGMENT = "fragment";
    /**
     * Supports <a href="https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html">form post</a>.
     */
    /*
       Part of CIL-592.
     */
     String RESPONSE_MODE_FORM_POST = "form_post";

     String FORM_ENCODING = "application/x-www-form-urlencoded";

    /**
        Token endpoint authorization methods are post and basic, as per OIDC spec.
     */
    String TOKEN_ENDPOINT_AUTH_POST = "client_secret_post";
    String TOKEN_ENDPOINT_AUTH_BASIC = "client_secret_basic";
    String TOKEN_ENDPOINT_AUTH_PRIVATE_KEY = "private_key_jwt";
    String TOKEN_ENDPOINT_AUTH_NONE = "none";

    String OA4MP_TOKEN_SIGNING_KEY_ID = "oa4mp:/jwt/signing/keyID";


}