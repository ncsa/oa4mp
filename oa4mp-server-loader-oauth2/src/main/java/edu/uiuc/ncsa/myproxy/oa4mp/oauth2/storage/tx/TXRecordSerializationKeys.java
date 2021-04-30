package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  9:04 AM
 */
public class TXRecordSerializationKeys extends SerializationKeys {
    public TXRecordSerializationKeys() {
        identifier("token_id"); // sets the default identifier for this
    }


    String audience = "audience";
    String expiresAt = "expires_at";
    String lifetime = "lifetime";
    String issuedAt = "issued_at";
    String issuer = "issuer";
    String isValid = "valid";
    String parentID = "parent_id";
    String resource = "resource";
    String scopes = "scopes";
    String tokenType = "token_type";

    public String audience(String... x) {
        if (0 < x.length) audience = x[0];
        return audience;
    }
    public String expiresAt(String... x) {
        if (0 < x.length) expiresAt = x[0];
        return expiresAt;
    }
    public String lifetime(String... x) {
        if (0 < x.length) lifetime = x[0];
        return lifetime;
    }
    public String issuedAt(String... x) {
        if (0 < x.length) issuedAt = x[0];
        return issuedAt;
    }
    public String issuer(String... x) {
        if (0 < x.length) issuer = x[0];
        return issuer;
    }
    public String isValid(String... x) {
        if (0 < x.length) isValid = x[0];
        return isValid;
    }

    public String parentID(String... x) {
        if (0 < x.length) parentID = x[0];
        return parentID;
    }

    public String resource(String... x) {
        if (0 < x.length) resource = x[0];
        return resource;
    }
    public String scopes(String... x) {
        if (0 < x.length) scopes = x[0];
        return scopes;
    }



    public String tokenType(String... x) {
        if (0 < x.length) tokenType = x[0];
        return tokenType;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys =  super.allKeys();
        allKeys.add(audience());
        allKeys.add(expiresAt());
        allKeys.add(lifetime());
        allKeys.add(issuedAt());
        allKeys.add(issuer());
        allKeys.add(isValid());
        allKeys.add(resource());
        allKeys.add(scopes());
        allKeys.add(parentID());
        allKeys.add(tokenType());

        return allKeys;
    }
}
