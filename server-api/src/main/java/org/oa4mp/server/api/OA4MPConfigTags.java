package org.oa4mp.server.api;

import edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags;
import edu.uiuc.ncsa.security.util.mail.MailConfigurationTags;

/**
 * These are the tag that are used in the XML configuration file.
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/12 at  8:42 AM
 */
public interface OA4MPConfigTags extends StorageConfigurationTags, MailConfigurationTags {
    // The next of these are the names of the stores used in configuration files.
    String CLIENTS_STORE = "clients";
    String CLIENT_APPROVAL_STORE = "clientApprovals";
    String ADMIN_CLIENT_STORE = "adminClients";
    String TRANSACTIONS_STORE = "transactions";
    String PERMISSION_STORE = "permissions";
    String TOKEN_EXCHANGE_RECORD_STORE = "txStore";
    String VIRTUAL_ORGANIZATION_STORE = "voStore";
    String JSON_STORE = "jsonStore";  // not in base OA4MP, but otherwise no reasonable place for this tag.

    String MYPROXY = "myproxy";
    String MYPROXY_PORT = "port";
    String MYPROXY_SOCKET_TIMEOUT = "socketTimeout";
    String MYPROXY_USE_PROXY = "useProxy";
    String MYPROXY_HOST = "host";
    String MYPROXY_LOA = "loa";
    String MYPROXY_LOA_NAME = "name";
    String MYPROXY_LOA_PORT = "port";
    String MYPROXY_SERVER_DN = "serverDN";
    String COMPONENT = "service"; // tag for top-level component of configuration

    String DEVICE_FLOW_SERVLET = "deviceFlowServlet"; // The name of the device flow servlet
    String DEVICE_FLOW_AUTHORIZATION_URI = "authorizationURI"; // Where the user goes to get a code
    String DEVICE_FLOW_SERVLET_URI = "verificationURI"; // Where the user goes give their code
    String DEVICE_FLOW_INTERVAL = "interval"; // If there is a different DF uri than the standard
    String DEVICE_FLOW_LIFETIME = "lifetime"; // If this is <= 0 , then the authorization grant lifetime is used.
    /**
     * The characters allowed for user codes.
     */
    String DEVICE_FLOW_CODE_CHARS = "codeChars"; // If there is a different DF uri than the standard
    /**
     * The number of actual characters in a user code. E.g. if this is 6, then 6 characters
     * will be created <b><i>before</i></b> it is divided up with the separator
     */
    String DEVICE_FLOW_USER_CODE_LENGTH = "codeLength"; // If there is a different DF uri than the standard
    /**
     * The character(s) to put between each period. So if
     * <ol>
     * <li>raw code = ABC123</li>
     * <li>separator = _</li>
     * <li>period length = 3</li>
     *     </ol>
     *     a user code of ABC_123 would be returned to the user.
     */
    String DEVICE_FLOW_CODE_SEPARATOR = "codeSeparator"; // If there is a different DF uri than the standard
    /**
     * The length of a period i.e., how many characters are together at once between separators. This is
     * a small number like 3, 4 or maybe 5 so that the user can just look at it and read it off.
     * If the user code were ABC123DEC456 then <br/><br/>
     * period = 3 ==> ABC_123_DEC_456<br/><br/>
     * period = 4 ==> ABC1_23DE_C456
     *
     */
    String DEVICE_FLOW_CODE_PERIOD_LENGTH = "codePeriodLength"; // If there is a different DF uri than the standard
    
    String AUTHORIZATION_SERVLET = "authorizationServlet"; // The name of the authz servlet


    // for proxy authorization
    String AUTHORIZATION_SERVLET_USE_PROXY = "useProxy"; // Use a proxy for authorization
    String AUTHORIZATION_SERVLET_PROXY_CONFIG_FILE = "cfgFile"; // The full path to the proxy configuration file
    String AUTHORIZATION_SERVLET_PROXY_CONFIG_NAME = "cfgName"; // The name of the configuration  to use.

    // For tomcat and remote header configuration
    String AUTHORIZATION_SERVLET_URI = "authorizationURI"; // If there is a different authorization uri than the standard, specify it here
    String AUTHORIZATION_SERVLET_HEADER_USE = "useHeader"; // If there is a header present, use it, otherwise ignore it.
    String AUTHORIZATION_SERVLET_HEADER_REQUIRE = "requireHeader"; // Require the header. This will cause an exception to be thrown if there is no header.
    String AUTHORIZATION_SERVLET_HEADER_FIELD_NAME = "headerFieldName"; // The name of the header field to be used for the username, e.g. REMOTE_USER
    String AUTHORIZATION_SERVLET_RETURN_DN_AS_USERNAME = "returnDnAsUsername"; // Use the first certificate's DN as the username that is returned to the OAuth client
    String AUTHORIZATION_SERVLET_SHOW_LOGON = "showLogon"; // show the username and password prompt.
    String AUTHORIZATION_SERVLET_VERIFY_USERNAME = "verifyUsername"; // Show the logon with only the username for verification (required by OAuth spec).
    String CONVERT_DN_TO_GLOBUS_ID = "convertDNToGlobusID"; // Convert a spec compliant DN (comma delimited) to Globus format (slash delimited)
    String MAX_ALLOWED_NEW_CLIENT_REQUESTS = "maxAllowedNewClientRequests"; // The name of the header field to be used for the username, e.g. REMOTE_USER
    String ENABLE_UTIL_SERVLET = "enableUtilServlet"; // attribute tag for enabling the util servlet
    String ENABLE_RFC8693_SUPPORT = "enableTokenExchange"; //
    String ENABLE_RFC8628_SUPPORT = "enableDeviceFlow"; //


    String MESSAGES = "messages";
    String SERVICE_ADDRESS = "address";


    String ID_SCHEME = "scheme";
    String ID_SPP = "schemeSpecificPart";

    String USERS = "users";
    String ARCHIVED_USERS = "archivedUsers";
    String IDENTITY_PROVIDERS = "identityProviders";
    String TWO_FACTOR = "twoFactor";
    String SEQUENCE = "sequence";
    String SERIAL_STRINGS= "serialStrings";
    String SERIAL_STRING_TOKEN= "token";
    String SERIAL_STRING_PREFIX= "prefix";
    String SERIAL_STRING_NS= "ns";
    /**
     * This starts every token (e.g., temp token, access token, verifier) and should be a valid URI.
     */
    String TOKEN_PREFIX= "tokenPrefix";
    String DISABLE_DEFAULT_STORES = "disableDefaultStores";
    String PINGABLE = "pingable"; // Property for server tag that determines whether ping interface is enabled.

}

