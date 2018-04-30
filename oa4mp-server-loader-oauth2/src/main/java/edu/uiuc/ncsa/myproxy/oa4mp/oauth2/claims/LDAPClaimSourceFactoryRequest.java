package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceFactoryRequest;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/16/16 at  3:51 PM
 */
public class LDAPClaimSourceFactoryRequest extends ClaimSourceFactoryRequest{
    public LDAPConfiguration getLdapConfiguration() {
        return ldapConfiguration;
    }

    LDAPConfiguration ldapConfiguration;
    public LDAPClaimSourceFactoryRequest(MyLoggingFacade logger, LDAPConfiguration ldap, Collection<String> scopes) {
        super(logger, scopes);
        ldapConfiguration = ldap;
    }


}
