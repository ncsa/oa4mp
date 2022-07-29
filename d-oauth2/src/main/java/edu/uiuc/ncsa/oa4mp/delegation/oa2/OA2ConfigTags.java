package edu.uiuc.ncsa.oa4mp.delegation.oa2;

/**
 * These are the tags in (XML) configuration files.
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  10:37 AM
 */
public interface OA2ConfigTags {
    /**
     * This overrides the discovery for the servlet and will be used globally. It may be overridden
     * on a per client basis as well.
     */
    public String ISSUER = "issuer";
    public String AUTH_GRANT_LIFETIME = "authorizationGrantLifetime"; // in seconds, convert to ms.
    public String MAX_AUTH_GRANT_LIFETIME = "maxAuthorizationGrantLifetime"; // in seconds, convert to ms.
    public String ACCESS_TOKEN_LIFETIME = "accessTokenLifetime"; // (old) default in seconds, convert to ms.
    public String DEFAULT_ACCESS_TOKEN_LIFETIME = "defaultAccessTokenLifetime"; // in seconds, convert to ms.
    public String MAX_ACCESS_TOKEN_LIFETIME = "maxAccessTokenLifetime"; // in seconds, convert to ms.
    public String DEFAULT_ID_TOKEN_LIFETIME = "defaultIDTokenLifetime"; // in seconds, convert to ms.
    public String MAX_ID_TOKEN_LIFETIME = "maxIDTokenLifetime"; // in seconds, convert to ms.
    public String REFRESH_TOKEN_ENABLED = "refreshTokenEnabled"; // Enable or disable refresh tokens for this server.
    public String REFRESH_TOKEN_LIFETIME = "refreshTokenLifetime"; // in seconds, convert to ms.
    public String MAX_REFRESH_TOKEN_LIFETIME = "maxRefreshTokenLifetime"; // in seconds, convert to ms.
    public String MAX_CLIENT_REFRESH_TOKEN_LIFETIME = "maxClientRefreshTokenLifetime"; // in seconds, convert to ms.
    public String OIDC_SUPPORT_ENABLED = "OIDCEnabled"; // Enable or disable OIDC support for this server.
    public String CLIENT_SECRET_LENGTH= "clientSecretLength"; // in bytes.
    public String ENABLE_TWO_FACTOR_SUPPORT= "enableTwoFactorSupport"; // boolean for enabling two factor support.
    // Note -- enabling two factor support boils down to not testing the connection early since the
    // password that is generated is good for exactly one use. Another complicating factor is latency: The chain of events
    // is that the user authenticates and then a callback to the client is made, which gets an access token, then
    // gets the cert. It is possible that if the generated password has a short lifetime, it will have expired by the
    // time this happens. That cannot be helped.

    /*
     * Tags for scopes element of configuration
     */
    /**
     * Tope level tag for all scopes
     */
    public String SCOPES = "scopes";
    /**
     * Tag for an individual scope.
     */
    public String SCOPE = "scope";
    public String SCOPE_ENABLED="enabled";
    /**
     * (Optional) the fully qualified path and class name of the handler for these scopes. Note
     * that only one handler for all scopes is allowed. If this is not found in the classpath,
     * then an error will be raised. Alternately, you can simply override the configuration loader
     * and specify your handler directly.
     */
    public String SCOPE_HANDLER = "handler";

    public String ADDITIONAL_PARAMETERS = "parameters";
    public String ADDITIONAL_PARAMETER = "parameter";
    public String PARAMETER_KEY = "key";


}
