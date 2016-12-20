package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandlerFactoryRequest;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/16/16 at  3:51 PM
 */
public class LDAPScopeHandlerFactoryRequest extends ScopeHandlerFactoryRequest {
    public LDAPConfiguration getLdapConfiguration() {
        return ldapConfiguration;
    }

    LDAPConfiguration ldapConfiguration;
    public LDAPScopeHandlerFactoryRequest(MyLoggingFacade logger, LDAPConfiguration ldap, Collection<String> scopes) {
        super(logger, scopes);
        ldapConfiguration = ldap;
    }


}
