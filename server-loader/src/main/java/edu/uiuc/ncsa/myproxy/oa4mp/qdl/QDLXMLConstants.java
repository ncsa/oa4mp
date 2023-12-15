package edu.uiuc.ncsa.myproxy.oa4mp.qdl;

import edu.uiuc.ncsa.qdl.xml.SerializationConstants;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/5/21 at  1:37 PM
 */
public interface QDLXMLConstants extends SerializationConstants {
    String TX_RECORD = "tx_record";
    String TOKEN_TYPE = "token_type";
    String AUDIENCE = "audience";
    String EXPIRES_AT_ATTR = "expires_at";
    String LIFETIME_ATTR = "lifetime";
    String ISSUED_AT_ATTR = "issue_at";
    String IS_VALID_ATTR = "is_valid";
    String ISSUER = "issuer";
    String PARENT_ID = "parent_id";
    String SCOPES = "scopes";
    String STORED_TOKEN = "stored_token";
    String RESOURCES = "resources";
    String STATE = "state";
    String ID_ATTR = "id";

    String VO_ENTRY = "virtual_organization";
    String VO_JSON_WEB_KEYS = "json_web_keys";
    String VO_DEFAULT_KEY = "default_key";
    String VO_TITLE = "title";
    String VO_LAST_MODIFIED = "last_modified_at";
    String VO_LAST_ACCESSED = "last_accessed_at";
    String VO_CREATED = "created_at";
    String VO_DISCOVERY_PATH = "discovery_path";
    // use issuer and id_attr from above

}
