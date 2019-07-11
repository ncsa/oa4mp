package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags;

/**
 * These are the tags that appear in the client XML configuration file.
* <p>Created by Jeff Gaynor<br>
* on 3/23/12 at  8:17 AM
*/
public interface ClientXMLTags extends StorageConfigurationTags{
    /**
     * Identifies the client block. A configuration for a client resides completely in one of these.
     */
    public static final String COMPONENT = "client";
    /**
     * The identifier used in client registration
     */
    public static final String ID = "id";
    /**
     * The callback uri to be used for every request. See also {@link ClientEnvironment#getCallback()}.
     */
    public static final String CALLBACK_URI = "callbackUri";
    public static final String BASE_URI = "serviceUri";
    public static final String INITIATE_URI = "initiateUri";
    public static final String USER_INFO_URI = "userInfoUri";
    public static final String REVOCATION_URI = "revocationUri";
    //public static final String AUTHORIZATION_URI = "authorizationUri";
    public static final String ACCESS_TOKEN_URI = "accessTokenUri";
    public static final String AUTHORIZE_TOKEN_URI = "authorizeUri";
    public static final String ASSET_URI = "assetUri";
    public static final String SECRET_KEY = "secret";
    public static final String PUBLIC_KEY = "publicKeyFile";
    public static final String PRIVATE_KEY = "privateKeyFile";
    public static final String CERT_LIFETIME = "lifetime";
    public static final String SKIN = "skin";
    public static final String MAX_ASSET_LIFETIME = "maxAssetLifetime";
    public static final String KEYPAIR_LIFETIME = "keypairLifetime";
    public static final String ENABLE_ASSET_CLEANUP = "enableAssetCleanup";
    public static final String SHOW_REDIRECT_PAGE = "showRedirectPage";
    public static final String ERROR_PAGE_PATH = "errorPagePath";
    public static final String REDIRECT_PAGE_PATH = "redirectPagePath";
    public static final String SUCCESS_PAGE_PATH = "successPagePath";
    public static final String OIDC_ENABLED = "OIDCEnabled";
    public static final String SHOW_ID_TOKEN = "showIDToken";
    public static final String USE_HTTP_BASIC_AUTHORIZATIION = "useHTTPBasicAuth";
    /**
     * Tag identifying the asset store.
     */
    public static final String ASSET_STORE = "assetStore";
}
