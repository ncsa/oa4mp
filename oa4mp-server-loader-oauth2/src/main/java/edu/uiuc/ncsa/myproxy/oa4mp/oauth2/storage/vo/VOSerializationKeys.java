package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/21 at  8:52 AM
 */
public class VOSerializationKeys extends SerializationKeys {
    public VOSerializationKeys() {
        identifier("vo_id"); // sets the default identifier for this
    }


    String created       = "created";
    String defaultKeyID  = "default_key_id";
    String discoveryPath = "discovery_path";
    String issuer        = "issuer";
    String jsonWebKeys   = "json_web_keys";
    String lastModified  = "last_modified";
    String title         = "title";
    String valid         = "valid";
    public String created(String... x) {
        if (0 < x.length) created = x[0];
        return created;
    }

    public String defaultKeyID(String... x) {
        if (0 < x.length) defaultKeyID = x[0];
        return defaultKeyID;
    }
    public String discoveryPath(String... x) {
        if (0 < x.length) discoveryPath = x[0];
        return discoveryPath;
    }
    public String issuer(String... x) {
        if (0 < x.length) issuer = x[0];
        return issuer;
    }
    public String jsonWebKeys(String... x) {
        if (0 < x.length) jsonWebKeys = x[0];
        return jsonWebKeys;
    }
    public String lastModified(String... x) {
        if (0 < x.length) lastModified = x[0];
        return lastModified;
    }
    public String title(String... x) {
        if (0 < x.length) title = x[0];
        return title;
    }
    public String valid(String... x) {
        if (0 < x.length) valid = x[0];
        return valid;
    }

}
