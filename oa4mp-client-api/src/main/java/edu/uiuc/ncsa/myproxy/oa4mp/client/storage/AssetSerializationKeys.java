package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * Keys used for serialization. In file stores, these are XML tags. In SQL databases, these are column names.
 * <p>Created by Jeff Gaynor<br>
 * on 1/28/13 at  3:40 PM
 */
public class AssetSerializationKeys extends SerializationKeys {
    String username = "username";
    String certificates = "certificate";
    String privateKey = "private_key";
    String redirect = "redirect_uri";
    String creationTime = "creation_ts";
    String token = "token";
    String certReq = "cert_req";

    public String token(String... x) {
        if (0 < x.length) token = x[0];
        return token;
    }

    public String certReq(String... x) {
        if (0 < x.length) certReq = x[0];
        return certReq;
    }

    public String username(String... x) {
        if (0 < x.length) username = x[0];
        return username;
    }

    public String certificates(String... x) {
        if (0 < x.length) certificates = x[0];
        return certificates;
    }

    public String privateKey(String... x) {
        if (0 < x.length) privateKey = x[0];
        return privateKey;
    }

    public String redirect(String... x) {
        if (0 < x.length) redirect = x[0];
        return redirect;
    }

    public String creationTime(String... x) {
        if (0 < x.length) creationTime = x[0];
        return creationTime;
    }


}
