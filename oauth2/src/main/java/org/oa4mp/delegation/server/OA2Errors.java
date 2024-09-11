package org.oa4mp.delegation.server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/15 at  1:43 PM
 */
public interface OA2Errors {
    String ERROR_URI_PARAMETER = "error_uri";


    // OIDC specific error codes that must be returned if the authorization fails.
    /**
     * The Authorization Server requires End-User interaction of some form to proceed. This error MAY be returned when
     * the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot be
     * completed without displaying a user interface for End-User interaction. \
     */
    String INTERACTION_REQUIRED = "interaction_required";
    /**
     * The Authorization Server requires End-User authentication. This error MAY be returned when the prompt parameter
     * value in the Authentication Request is none, but the Authentication Request cannot be completed without
     * displaying a user interface for End-User authentication.
     */
    String LOGIN_REQUIRED = "login_required";
    /**
     * The End-User is REQUIRED to select a session at the Authorization Server. The End-User MAY be authenticated at
     * the Authorization Server with different associated accounts, but the End-User did not select a session. This
     * error MAY be returned when the prompt parameter value in the Authentication Request is none, but the
     * Authentication Request cannot be completed without displaying a user interface to prompt for a session to use.
     */
    String ACCOUNT_SELECTION_REQUIRED = "account_selection_required";
    /**
     * The Authorization Server requires End-User consent. This error MAY be returned when the prompt parameter value
     * in the Authentication Request is none, but the Authentication Request cannot be completed without displaying a
     * user interface for End-User consent.
     */
    String CONSENT_REQUIRED = "consent_required";
    /**
     * The request_uri in the Authorization Request returns an error or contains invalid data.
     */
    String INVALID_REQUEST_URI = "invalid_request_uri";
    /**
     * The request parameter contains an invalid Request Object.
     */
    String INVALID_REQUEST_OBJECT = "invalid_request_object";
    /**
     * The OP does not support use of the request parameter defined in Section 6.
     */
    String REQUEST_NOT_SUPPORTED = "request_not_supported";
    /**
     * The OP does not support use of the request_uri parameter defined in Section 6.
     */
    String REQUEST_URI_NOT_SUPPORTED = "request_uri_not_supported";
    /**
     * The OP does not support use of the registration parameter defined in Section 7.2.1.
     */
    String REGISTRATION_NOT_SUPPORTED = "registration_not_supported";
    /**
     * The request is missing a required parameter, includes an
     * invalid parameter value, includes a parameter more than
     * once, or is otherwise malformed.
     */
    String INVALID_REQUEST = "invalid_request";
    /**
     * The client is not authorized to request an authorization
     * code using this method.
     */
    String UNAUTHORIZED_CLIENT = "unauthorized_client";
    /**
     * The resource owner or authorization server denied the request.
     */
    String ACCESS_DENIED = "access_denied";
    /**
     * The authorization server does not support obtaining an
     * authorization code using this method.
     */
    String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    /**
     * The requested scope is invalid, unknown, or malformed.
     */
    String INVALID_SCOPE = "invalid_scope";
    /**
     * The authorization server encountered an unexpected
     * condition that prevented it from fulfilling the request.
     * (This error code is needed because a 500 Internal Server
     * Error HTTP status code cannot be returned to the client
     * via an HTTP redirect.)
     */
    String SERVER_ERROR = "server_error";
    /**
     * The authorization server is currently unable to handle
     * the request due to a temporary overloading or maintenance
     * of the server.  (This error code is needed because a 503
     * Service Unavailable HTTP status code cannot be returned
     * to the client via an HTTP redirect.)
     */
    String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
    /**
     * Specifically for the userInfo and getCert endpoints. This is used whenever a token is encountered
     * that is not valid (for whatever reason).
     */
     String INVALID_TOKEN = "invalid_token";

    /**
     * Used in the access servlet when a grant is presented that is either expired or invalid.
     */
    String INVALID_GRANT = "invalid_grant";

    String INVALID_TARGET = "invalid_target";

}
