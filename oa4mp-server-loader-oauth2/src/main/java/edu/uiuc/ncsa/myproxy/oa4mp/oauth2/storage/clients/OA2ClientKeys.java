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
    String atLifetime = "at_lifetime";
    String audience="audience";
    String callback_uri = "callback_uri";
    String config = "cfg";
    String dfInterval="df_interval";
    String dfLifetime="df_lifetime";
    String extended_attributes = "extended_attributes";
    String issuer = "issuer";
    String ldap = "ldap";
    String proxyClaimsList ="proxy_claims_list";
    String publicClient="public_client";
    String rtLifetime = "rt_lifetime";
    String resource="resource";
    String signTokens="sign_tokens";
    String skipServerScripts="skip_server_scripts";
    String scopes = "scopes";
    String strictScopes="strict_scopes";
    /*
      If you add attributes, make sure you update
           edu.uiuc.ncsa.oa2.qdl.storage.ClientStemMC
           (in  oa4mp-qdl)
      or you may break the QDL module that handles clients.
     */

    public String proxyClaimsList(String... x) {
           if (0 < x.length) proxyClaimsList = x[0];
           return proxyClaimsList;
       }

    public String skipServerScripts(String... x) {
           if (0 < x.length) skipServerScripts = x[0];
           return skipServerScripts;
       }


    public String dfLifetime(String... x) {
           if (0 < x.length) dfLifetime= x[0];
           return dfLifetime;
       }

    public String dfInterval(String... x) {
           if (0 < x.length) dfInterval= x[0];
           return dfInterval;
       }

    public String audience(String... x) {
           if (0 < x.length) audience= x[0];
           return audience;
       }

    public String resource(String... x) {
           if (0 < x.length) resource= x[0];
           return resource;
       }

     public String strictScopes(String... x) {
         if (0 < x.length) strictScopes= x[0];
         return strictScopes;
     }

    public String atLifetime(String... x) {
        if (0 < x.length) atLifetime= x[0];
        return atLifetime;
    }

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
        allKeys.add(proxyClaimsList());
        allKeys.add(rtLifetime());
        allKeys.add(atLifetime());
        allKeys.add(scopes());
        allKeys.add(signTokens());
        allKeys.add(ea());
        allKeys.add(strictScopes());
        allKeys.add(dfLifetime());
        allKeys.add(dfInterval());
        allKeys.add(skipServerScripts());
        return allKeys;
    }
}
