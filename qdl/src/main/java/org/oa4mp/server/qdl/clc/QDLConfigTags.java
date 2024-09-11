package org.oa4mp.server.qdl.clc;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/23 at  3:39 PM
 */
public interface QDLConfigTags {


     String ENABLE_OIDC = "enable_oidc";
    String ASSET_FILE_STORE_PATH = "path";
    String ASSET_STORE_TYPE = "type";
    String AUTHORIZE_URL = "authorization";
    String CALLBACK = "callback";
    String CLIENT_MANAGEMENT_URL = "client_management";
    String DEBUG_LEVEL = "debug_level";
    String DEVICE_AUTHORIZATION_URL = "device";
    String ENABLE_ASSET_CLEANUP = "enable_asset_cleanup";
    String ENDPOINTS = "endpoints";
    String EXTENDED_ATTRIBUTES = "extended_attributes";
    String EXTENDS = "extends";
    String FILE_STORE_REMOVE_EMPTY = "remove_empty_files";
    String FILE_STORE_REMOVE_FAILED = "remove_failed_files";
    String ID = "id";
    String INTROSPECTION_URL = "introspection";
    String JWKS = "jwks";
    String JWK_ID = "kid";
    String LOGGING_COUNT = "count";
    String LOGGING_DISABLE_LOG4J = "disable_log4j";
    String LOGGING_ENABLE_APPEND = "append_on";
    String LOGGING_FILE = "file";
    String LOGGING_MAX_SIZE = "max_size";
    String LOGGING_NAME = "name";
    String LOGGING_TAG = "logging";
    String MAX_ASSET_LIFETIME = "asset_lifetime";
    String REVOCATION_URL = "revocation";
    String SCOPES = "scopes";
    String SECRET = "secret";
    String SERVICE_URL = "service_uri";
    String SKIN = "skin";
    String SSL = "ssl";
    String SSL_USE_JAVA_TRUST_STORE = "use_java";
    String TOKEN_URL = "token";
    String TRUST_STORE_TAG = "trust_store";
    String KEY_STORE_TAG = "key_store";
    String TRUST_STORE_CERT_DN = "cert_dn";
    String TRUST_STORE_PASSWORD = "password";
    String TRUST_STORE_PATH = "path";
    String TRUST_STORE_TYPE = "type";
    String TRUST_STORE_STRICT_HOSTNAME = "strict_hostnames";
    String TRUST_STORE_USE_DEFAULT_TRUST_MANAGER = "use_default_trust_manager";
    String USER_INFO_URL = "user_info";
    String WELL_KNOWN_URL = "well_known";
    /*
    [root]
     [root.logging]
     [root.assets]
     [root.ssl]
     useJavaTrustStore:=true
       [root.ssl.trust_store]
       path:='/home/ncsa/certs/localhost-2020.jks'
       password:='vnlH814i'
       type:='JWK'
       certDN:='CN=localhost'

    [commandline2]
    id:='ashigaru:command.line2'
    kid:='EC9FCFCB3716AC4C2279DF42EC98CABF'
    extends:='root'
     */
}
