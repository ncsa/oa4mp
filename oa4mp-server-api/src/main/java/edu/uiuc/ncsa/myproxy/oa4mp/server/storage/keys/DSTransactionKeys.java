package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.keys;

import edu.uiuc.ncsa.security.delegation.server.storage.support.ServiceTransactionKeys;

/**
* <p>Created by Jeff Gaynor<br>
* on 4/25/12 at  3:08 PM
*/
public class DSTransactionKeys extends ServiceTransactionKeys {

    String certReq = "certreq";
    String cert = "certificate";
    String clientKey = "oauth_consumer_key";
    String username = "username";
    String myproxyUsername = "myproxyUsername";

    public String myproxyUsername(String... x) {
        if (0 < x.length) myproxyUsername = x[0];
        return myproxyUsername;
    }

    public String certReq(String... x) {
        if (0 < x.length) certReq = x[0];
        return certReq;
    }

    public String cert(String... x) {
        if (0 < x.length) cert = x[0];
        return cert;
    }

    public String clientKey(String... x) {
        if (0 < x.length) clientKey = x[0];
        return clientKey;
    }

    public String username(String... x) {
        if (0 < x.length) username = x[0];
        return username;
    }

}
