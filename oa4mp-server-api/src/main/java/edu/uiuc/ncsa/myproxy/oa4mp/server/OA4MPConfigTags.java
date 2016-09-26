package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags;
import edu.uiuc.ncsa.security.util.mail.MailConfigurationTags;

/**
 * These are the tag that are used in the XML configuration file.
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  8:42 AM
 */
public interface OA4MPConfigTags extends StorageConfigurationTags, MailConfigurationTags {
    public static final String CLIENTS_STORE = "clients";
    public static final String TRANSACTIONS_STORE = "transactions";
    public static final String CLIENT_APPROVAL_STORE = "clientApprovals";

    public static final String MYPROXY = "myproxy";
    public static final String MYPROXY_PORT = "port";
    public static final String MYPROXY_SOCKET_TIMEOUT = "socketTimeout";
    public static final String MYPROXY_HOST = "host";
    public static final String MYPROXY_LOA = "loa";
    public static final String MYPROXY_LOA_NAME = "name";
    public static final String MYPROXY_LOA_PORT = "port";
    public static final String MYPROXY_SERVER_DN = "serverDN";
    public static final String SSL_KEYSTORE = "keystore";
    public static final String SSL_KEYSTORE_PATH = "path";
    public static final String SSL_KEYSTORE_PASSWORD = "password";
    public static final String SSL_KEYSTORE_TYPE = "type";
    public static final String SSL_KEYSTORE_FACTORY = "factory";
    public static final String SSL_KEYSTORE_USE_JAVA_KEYSTORE = "useJavaKeystore";
    public static final String COMPONENT = "service"; // tag for top-level component of configuration


    public static final String AUTHORIZATION_SERVLET = "authorizationServlet"; // The name of the servlet
    public static final String AUTHORIZATION_SERVLET_HEADER_USE = "useHeader"; // If there is a header present, use it, otherwise ignore it.
    public static final String AUTHORIZATION_SERVLET_HEADER_REQUIRE = "requireHeader"; // Require the header. This will cause an exception to be thrown if there is no header.
    public static final String AUTHORIZATION_SERVLET_HEADER_FIELD_NAME = "headerFieldName"; // The name of the header field to be used for the username, e.g. REMOTE_USER
	public static final String AUTHORIZATION_SERVLET_RETURN_DN_AS_USERNAME = "returnDnAsUsername"; // Use the first certificate's DN as the username that is returned to the OAuth client
	public static final String AUTHORIZATION_SERVLET_SHOW_LOGON = "showLogon"; // show the username and password prompt.
	public static final String AUTHORIZATION_SERVLET_VERIFY_USERNAME = "verifyUsername"; // Show the logon with only the username for verification (required by OAuth spec).
	public static final String CONVERT_DN_TO_GLOBUS_ID = "convertDNToGlobusID"; // Convert a spec compliant DN (comma delimited) to Globus format (slash delimited)
    public static final String MAX_ALLOWED_NEW_CLIENT_REQUESTS = "maxAllowedNewClientRequests"; // The name of the header field to be used for the username, e.g. REMOTE_USER


/*
    public static final String HEADER_FIELD = "headerField"; // The name of the header field to be used for the username, e.g. REMOTE_USER
    public static final String HEADER_FIELD_USE = "headerField"; // How to use the header field. Possibilies are mandatory, ignore, optional

    public static final int HEADER_FIELD_IGNORE = 0;
    public static final int HEADER_FIELD_REQUIRE = 10;
    public static final int HEADER_FIELD_OPTIONAL = 100;
*/

    public static final String MESSAGES = "messages";
    public static final String SERVICE_ADDRESS = "address";


    public static final String DEBUG = "debug";
    public static final String USERS = "users";
    public static final String ARCHIVED_USERS = "archivedUsers";
    public static final String IDENTITY_PROVIDERS = "identityProviders";
    public static final String TWO_FACTOR = "twoFactor";
    public static final String SEQUENCE = "sequence";
    public static final String SERIAL_STRINGS= "serialStrings";
    public static final String SERIAL_STRING_TOKEN= "token";
    public static final String SERIAL_STRING_PREFIX= "prefix";
    public static final String SERIAL_STRING_NS= "ns";
    /**
     * This starts every token (e.g., temp token, access token, verifier) and should be a valid URI.
     */
    public static final String TOKEN_PREFIX= "tokenPrefix";
    public static final String DISABLE_DEFAULT_STORES = "disableDefaultStores";
    public static final String PINGABLE = "pingable"; // Property for server tag that determines whether ping interface is enabled.

}

