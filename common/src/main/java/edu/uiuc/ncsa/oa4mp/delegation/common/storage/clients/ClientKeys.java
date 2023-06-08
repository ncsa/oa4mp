package edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/25/12 at  3:06 PM
 */
public class ClientKeys extends BaseClientKeys {
    public ClientKeys() {
        identifier("oauth_consumer_key");
    }

    String errorURL = "error_url";
    String homeURL = "home_url";
    String proxyLimited = "proxy_limited";

    String rfc7523Client = "rfc7523_client";

    public String rfc7523Client(String... x) {
        if (0 < x.length) rfc7523Client = x[0];
        return rfc7523Client;
    }


    public String proxyLimited(String... x) {
        if (0 < x.length) proxyLimited = x[0];
        return proxyLimited;
    }

    public String homeURL(String... x) {
        if (0 < x.length) homeURL = x[0];
        return homeURL;
    }


    public String errorURL(String... x) {
        if (0 < x.length) errorURL = x[0];
        return errorURL;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(proxyLimited());
        allKeys.add(homeURL());
        allKeys.add(errorURL());
        allKeys.add(rfc7523Client());
        return allKeys;
    }
}
