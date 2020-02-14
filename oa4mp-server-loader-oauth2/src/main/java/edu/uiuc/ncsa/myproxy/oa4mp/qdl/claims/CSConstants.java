package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

/**
 * The constants for creating claim sources so that they are centralized.
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
    /*
    Specific values for specific configurations
     */

    /*
    File based claim sources
     */
    public String CS_FILE_FILE_PATH = "file_path";
    public String CS_FILE_CLAIM_KEY = "claim_key";

    /*
    HTTP headers based claim sources
     */
    public String CS_HEADERS_PREFIX = "prefix";

    /*
    LDAP based claim sources
     */
    public String CS_LDAP_AUTHZ_TYPE = "authz_type";
    public String CS_LDAP_CONTEXT_NAME = "context";
    public String CS_LDAP_SEARCH_ATTRIBUTES = "search_attributes."; // attributes in LDAP to get.
    public String CS_LDAP_GROUP_NAMES = "group_names."; // search attributes that are groups
    public String CS_LDAP_RENAME = "rename."; // new names of returned attributes, stem.old_name := new_name
    public String CS_LDAP_LISTS = "list."; // attributes that should be returned as lists
    public String CS_LDAP_PASSWORD = "password";
    public String CS_LDAP_PORT = "port";
    public String CS_LDAP_SEARCH_FILTER_ATTRIBUTE = "claim_name"; // the name of the claim to look up and get
    public String CS_LDAP_SEARCH_BASE = "search_base";
    public String CS_LDAP_SEARCH_NAME = "search_name";
    public String CS_LDAP_SERVER_ADDRESS = "address";
    public String CS_LDAP_SECURITY_PRINCIPAL = "username";

}
