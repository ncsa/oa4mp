package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions;

import edu.uiuc.ncsa.security.delegation.server.storage.support.ServiceTransactionKeys;

import java.util.List;

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

    @Override
    public List<String> allKeys() {
        List<String> allKeys =  super.allKeys();
        allKeys.add(myproxyUsername());
        allKeys.add(certReq());
        allKeys.add(cert());
        allKeys.add(clientKey());
        allKeys.add(username());
        return allKeys;

    }
}
