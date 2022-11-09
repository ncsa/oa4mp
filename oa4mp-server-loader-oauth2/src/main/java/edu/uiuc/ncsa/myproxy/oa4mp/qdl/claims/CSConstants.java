package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

/**
 * The constants for creating claim sources so that they are centralized.  These are the property names that
 * appear in QDL configuration objects.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  6:31 AM
 */
public interface CSConstants {
    /*
    General constants for all configurations
     */
    public String CS_DEFAULT_FAIL_ON_ERROR = "fail_on_error";
    public String CS_DEFAULT_NOTIFY_ON_FAIL = "notify_on_fail";
    public String CS_DEFAULT_IS_ENABLED = "enabled";
    public String CS_DEFAULT_ID = "id";
    public String CS_DEFAULT_NAME = "name";
    public String CS_DEFAULT_ID_VALUE = "qdl_claim_source";
    public String CS_DEFAULT_TYPE = "type";

    /*
    Types of configurations supported
     */
    public String CS_TYPE_FILE = "file";
    public String CS_TYPE_LDAP = "ldap";
    public String CS_TYPE_NCSA = "ncsa";
    public String CS_TYPE_HEADERS = "http";
    public String CS_TYPE_CODE = "code";
    /*
    Specific values for specific configurations
     */

    /*
       Code-base claim source
     */
    public String CS_CODE_JAVA_CLASS = "java_class";

    /*
    File based claim sources
     */
    public String CS_FILE_FILE_PATH = "file_path";
    public String CS_FILE_CLAIM_KEY = "claim_key";
    public String CS_USE_DEFAULT_KEY = "use_default";
    public String CS_DEFAULT_CLAIM_NAME_KEY = "default_claim";

    /*
    HTTP headers based claim sources
     */
    public String CS_HEADERS_PREFIX = "prefix";

    /*
    LDAP based claim sources
     */
    String CS_LDAP_ADDITIONAL_FILTER = "filter"; // the name of the LDAP context or object to search. Very necessary when you need it. Defaults to "".
    String CS_LDAP_AUTHZ_TYPE = "auth_type"; // Must be none, simple or strong.
    String CS_LDAP_CONTEXT_NAME = "context"; // the name of the LDAP context or object to search. Very necessary when you need it. Defaults to "".
    String CS_LDAP_GROUP_NAMES = "groups"; // search attributes that are parsed in to groups
    String CS_LDAP_LISTS = "lists"; // attributes that should be returned as lists, i.e. multi-valued rather than first one found
    String CS_LDAP_PASSWORD = "password"; // Ditto username.
    String CS_LDAP_PORT = "port"; // This can be omitted. we always use SSL, so it defaults to 636
    String CS_LDAP_RENAME = "rename"; // new names of returned attributes, stem.old_name := new_name
    String CS_LDAP_SEARCH_NAME = "claim_name"; // The name of the claim to use. If not present in the claims, an exception is thrown
    String CS_LDAP_SEARCH_ATTRIBUTES = "search_attributes"; // attributes in LDAP to get. Omitting means get ALL of them
    String CS_LDAP_SEARCH_BASE = "search_base"; // The path in LDAP to start the search.

    String CS_LDAP_SEARCH_SCOPE = "search_scope"; // The  LDAP search scope.
    String CS_LDAP_SEARCH_SCOPE_OBJECT = "object"; // The  LDAP search scope.
    String CS_LDAP_SEARCH_SCOPE_ONE_LEVEL = "one_level"; // The  LDAP search scope.
    String CS_LDAP_SEARCH_SCOPE_SUBTREE = "subtree"; // The  LDAP search scope.
    String CS_LDAP_SEARCH_FILTER_ATTRIBUTE = "ldap_name"; // the name of the attribute in LDAP to search on.
    String CS_LDAP_SECURITY_PRINCIPAL = "username"; // only needed if authz type is simple or strong
    String CS_LDAP_SERVER_ADDRESS = "address"; // required

}
