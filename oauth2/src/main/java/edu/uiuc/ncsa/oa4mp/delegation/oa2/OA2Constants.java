package edu.uiuc.ncsa.oa4mp.delegation.oa2;

/**
 * Constants that are used as e.g. parameters in client requests
 * <p>Created by Jeff Gaynor<br>
 * on 9/24/13 at  1:17 PM
 */
public interface OA2Constants {

    public static String ACCESS_TOKEN = "access_token";
    public static String ACCESS_TYPE = "access_type";

    /**
     * This is used for the code=grant token when getting the access
     * token. It looks like  {@link #RESPONSE_TYPE_CODE} (same value).
     * Use the right one in case something chages in the spec!
     */
    public static String AUTHORIZATION_CODE = "code";
    public static String REFRESH_LIFETIME = "rt_lifetime";
    public static String MAX_REFRESH_LIFETIME = "max_rt_lifetime";
    public static String ACCESS_TOKEN_LIFETIME = "at_lifetime";
    public static String MAX_ACCESS_TOKEN_LIFETIME = "max_at_lifetime";
    public static String STRICT_SCOPES = "strict_scopes";
    public static String DESCRIPTION = "description";
    public static String SKIP_SERVER_SCRIPTS = "skip_server_scripts";
    public static String CERT_LIFETIME = "certlifetime";
    public static String CERT_REQ = "certreq";
    public static String CLIENT_ID = "client_id";
    public static String CLIENT_SECRET = "client_secret";
    public static String DISPLAY = "display";
    public static String ERROR = "error";
    public static String ERROR_DESCRIPTION = "error_description";
    public static String ERROR_URI = "error_uri";
    public static String EXPIRES_IN = "expires_in";
    /**
     * Used as the parameter for the grant type, e.g. grant_type="authorization_code"
     */
    public static String GRANT_TYPE = "grant_type";
    /**
     * Use with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     */
    public static String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    /**
     * Use with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     */
    public static String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    /**
     * Use for <a href="https://tools.ietf.org/html/rfc6749#section-4.2">implicit flow.</a>
     */
    public static String GRANT_TYPE_IMPLICIT = "implicit";

    // CIL-1101
    public static String GRANT_TYPE_DEVICE_FLOW = "urn:ietf:params:oauth:grant-type:device_code";

    // CIL-771 proposed grant type
    String GRANT_TYPE_TOKEN_INFO = "urn:oa4mp:params:oauth:grant-type:token-info";

    public static String NONCE = "nonce";
    public static String PROMPT = "prompt";
    public static String MAX_AGE = "max_age";
    public static String AUTH_GRANT_TOKEN_LIFETIME = "auth_grant_lifetime";
    public static String ID_TOKEN_HINT = "id_token_hint";
    public static String ID_TOKEN = "id_token";
    public static String ID_TOKEN_LIFETIME = "id_token_lifetime";
    public static String MAX_ID_TOKEN_LIFETIME = "max_id_token_lifetime";
    public static String ID_TOKEN_IDENTIFIER = "jti"; // was token_id
    public static String EA_SUPPORT = "ea_support";
    public static String REQUEST = "request";
    public static String REQUEST_URI = "request_uri";
    public static String AUTHORIZATION_TIME = "auth_time";

    public static String PROMPT_NONE = "none";
    public static String PROMPT_LOGIN = "login";
    public static String PROMPT_CONSENT = "consent";
    public static String PROMPT_SELECT_ACCOUNT = "select_account";
    public static String DISPLAY_PAGE = "page";
    public static String DISPLAY_POPUP = "popup";
    public static String DISPLAY_TOUCH = "touch";
    public static String DISPLAY_WAP = "wap";

    public static String REDIRECT_URI = "redirect_uri";
    public static String REFRESH_TOKEN = "refresh_token";
    /**
     * Used as the parameter to denote the response type, e.g. response_type="code"
     */
    public static String RESPONSE_TYPE = "response_type";

    /**
     * Used with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     */
    public static String RESPONSE_TYPE_CODE = "code";
    /**
     * Used with <a href="https://tools.ietf.org/html/rfc6749#section-4.1">authorization code grant</a>
     * <b>and</b> <a href="https://tools.ietf.org/html/rfc6749#section-4.2">implicit flow grant.</a>
     */
    public static String RESPONSE_TYPE_ID_TOKEN = "id_token";
    /**
     * Only used with <a href="https://tools.ietf.org/html/rfc6749#section-4.2">implicit flow grant.</a>
     */
    public static String RESPONSE_TYPE_TOKEN = "token";
    /**
     * Recently added
     */
    public static String RESPONSE_TYPE_NONE = "none";

    public static String STATE = "state";
    public static String SCOPE = "scope";
    public static String TOKEN_TYPE = "token_type";
    public static String BEARER_TOKEN_TYPE = "Bearer";
    /**
     * Use {@link #GRANT_TYPE_AUTHORIZATION_CODE}. Used to be only possible one but
     * we have more now...
     * @deprecated
     */
    public static String AUTHORIZATION_CODE_VALUE = "authorization_code";
    /**
     * as per <a href="https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes">the open id spec</a>
     */
    public static String RESPONSE_MODE = "response_mode";
    public static String RESPONSE_MODE_QUERY = "query";
    public static String RESPONSE_MODE_FRAGMENT = "fragment";
    /**
     * Supports <a href="https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html">form post</a>.
     */
    /*
       Part of CIL-592.
     */
    public static String RESPONSE_MODE_FORM_POST = "form_post";

    public static String FORM_ENCODING = "application/x-www-form-urlencoded";

    /**
        Token endpoint authorization methods are post and basic, as per OIDC spec.
     */
    String TOKEN_ENDPOINT_AUTH_POST = "client_secret_post";
    String TOKEN_ENDPOINT_AUTH_BASIC = "client_secret_basic";
    String TOKEN_ENDPOINT_AUTH_PRIVATE_KEY = "private_key_jwt";
    String TOKEN_ENDPOINT_AUTH_NONE = "none";



}