package edu.uiuc.ncsa.myproxy.oa4mp.qdl;

import edu.uiuc.ncsa.qdl.xml.XMLConstants;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/5/21 at  1:37 PM
 */
public interface QDLXMLConstants extends XMLConstants {
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
    String RESOURCES = "resources;";
    String ID_ATTR = "id";

    /*
        String tokenType;
    List<String> audience;
    long expiresAt = System.currentTimeMillis();
    long lifetime = 0L;
    long issuedAt = System.currentTimeMillis();
    String issuer;
    Identifier parentID;
    List<String> scopes;
    List<URI> resource;
    boolean valid;
     */
}
