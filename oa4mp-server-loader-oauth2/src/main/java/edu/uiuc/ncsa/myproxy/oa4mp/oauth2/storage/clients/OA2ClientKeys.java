package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;


import edu.uiuc.ncsa.security.delegation.storage.ClientKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/14/14 at  1:05 PM
 */
public class OA2ClientKeys extends ClientKeys {
    public OA2ClientKeys() {
        super();
        identifier("client_id");
        secret("public_key");
    }
    String issuer = "issuer";
    String callback_uri = "callback_uri";
    String rtLifetime = "rt_lifetime";
    String scopes = "scopes";
    String ldap = "ldap";

    String config = "cfg";
    String extended_attributes = "extended_attributes";
    String signTokens="sign_tokens";
    String publicClient="public_client";

     public String issuer(String... x) {
         if (0 < x.length) issuer= x[0];
         return issuer;
     }

    public String ea(String... x) {
        if (0 < x.length) extended_attributes = x[0];
        return extended_attributes;
    }

    public String publicClient(String... x) {
        if (0 < x.length) publicClient= x[0];
        return publicClient;
    }


    public String signTokens(String... x) {
        if (0 < x.length) signTokens= x[0];
        return signTokens;
    }


    public String callbackUri(String... x) {
        if (0 < x.length) callback_uri = x[0];
        return callback_uri;
    }


    public String rtLifetime(String... x) {
        if (0 < x.length) rtLifetime = x[0];
        return rtLifetime;
    }


    public String scopes(String... x) {
        if (0 < x.length) scopes = x[0];
        return scopes;
    }


    public String ldap(String... x) {
        if (0 < x.length) ldap = x[0];
        return ldap;
    }


    public String cfg(String... x) {
        if (0 < x.length) config = x[0];
        return config;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(callbackUri());
        allKeys.add(cfg());
        allKeys.add(issuer());
        allKeys.add(ldap());
        allKeys.add(publicClient());
        allKeys.add(rtLifetime());
        allKeys.add(scopes());
        allKeys.add(signTokens());
        allKeys.add(ea());
        return allKeys;
    }
}
