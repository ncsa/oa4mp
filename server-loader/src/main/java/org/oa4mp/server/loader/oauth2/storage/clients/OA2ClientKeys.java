package org.oa4mp.server.loader.oauth2.storage.clients;


import org.oa4mp.delegation.common.storage.clients.ClientKeys;

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
    String allowPromptNone = "allow_prompt_none";
    String idTokenLifetime = "idt_lifetime";
    String audience="audience";
    String callback_uri = "callback_uri";
    String config = "cfg";
    String dfInterval="df_interval";
    String dfLifetime="df_lifetime";
    String ersatzClient="ersatz_client";
    String ersatzInheritIDToken = "ersatz_inherit_id_token";
    String extended_attributes = "extended_attributes";
    String extendsProvisioners = "extends_provisioners";
    String forwardScopesToProxy = "forward_scopes_to_proxy";
    String issuer = "issuer";
    String ldap = "ldap";
    String maxATLifetime = "at_max_lifetime";
    String maxRTLifetime = "rt_max_lifetime";
    String maxIDTLifetime = "idt_max_lifetime";
    String proxyClaimsList ="proxy_claims_list";
    String proxyRequestScopes ="proxy_request_scopes";
    String publicClient="public_client";
    String rtLifetime = "rt_lifetime";
    String rtGracePeriod = "rt_grace_period";
    String resource="resource";
    String signTokens="sign_tokens";
    String skipServerScripts="skip_server_scripts";
    String scopes = "scopes";
    String strictScopes="strict_scopes";
    String prototypes ="prototypes";

    /*
      If you add attributes, make sure you update
           edu.uiuc.ncsa.oa2.qdl.storage.ClientStemMC
           (in  oa4mp-qdl)
      or you may break the QDL module that handles clients.
     */

    public String allowPromptNone(String... x) {
        if (0 < x.length) allowPromptNone = x[0];
        return allowPromptNone;
    }
    public String idtLifetime(String... x) {
           if (0 < x.length) idTokenLifetime = x[0];
           return idTokenLifetime;
       }
    public String maxIDTLifetime(String... x) {
           if (0 < x.length) maxIDTLifetime = x[0];
           return maxIDTLifetime;
       }


    public String proxyRequestScopes(String... x) {
           if (0 < x.length) proxyRequestScopes = x[0];
           return proxyRequestScopes;
       }

    public String ersatzInheritIDToken(String... x) {
           if (0 < x.length) ersatzInheritIDToken = x[0];
           return ersatzInheritIDToken;
       }

    public String forwardScopesToProxy(String... x) {
           if (0 < x.length) forwardScopesToProxy = x[0];
           return forwardScopesToProxy;
       }


    public String prototypes(String... x) {
           if (0 < x.length) prototypes = x[0];
           return prototypes;
       }

    public String maxATLifetime(String... x) {
           if (0 < x.length) maxATLifetime = x[0];
           return maxATLifetime;
       }

    public String maxRTLifetime(String... x) {
           if (0 < x.length) maxRTLifetime = x[0];
           return maxRTLifetime;
       }


    public String extendsProvisioners(String... x) {
           if (0 < x.length) extendsProvisioners = x[0];
           return extendsProvisioners;
       }

    public String ersatzClient(String... x) {
           if (0 < x.length) ersatzClient = x[0];
           return ersatzClient;
       }

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
    public String rtGracePeriod(String... x) {
        if (0 < x.length) rtGracePeriod = x[0];
        return rtGracePeriod;
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
        allKeys.add(atLifetime());
        allKeys.add(audience());
        allKeys.add(callbackUri());
        allKeys.add(cfg());
        allKeys.add(dfInterval());
        allKeys.add(dfLifetime());
        allKeys.add(ea());
        allKeys.add(ersatzClient());
        allKeys.add(ersatzInheritIDToken());
        allKeys.add(extendsProvisioners());
        allKeys.add(forwardScopesToProxy());
        allKeys.add(idtLifetime());
        allKeys.add(issuer());
        allKeys.add(ldap());
        allKeys.add(maxATLifetime());
        allKeys.add(maxIDTLifetime());
        allKeys.add(maxRTLifetime());
        allKeys.add(prototypes());
        allKeys.add(proxyClaimsList());
        allKeys.add(proxyRequestScopes());
        allKeys.add(publicClient());
        allKeys.add(rtGracePeriod());
        allKeys.add(resource());
        allKeys.add(rtLifetime());
        allKeys.add(scopes());
        allKeys.add(signTokens());
        allKeys.add(skipServerScripts());
        allKeys.add(strictScopes());
        return allKeys;
    }
}
