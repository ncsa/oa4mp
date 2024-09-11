package org.oa4mp.server.loader.oauth2.claims;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.server.server.claims.ClaimSourceFactoryRequest;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/16/16 at  3:51 PM
 */
public class LDAPClaimSourceFactoryRequest extends ClaimSourceFactoryRequest{
    public LDAPConfiguration getLdapConfiguration() {
        return (LDAPConfiguration)getConfiguration();
    }

    public LDAPClaimSourceFactoryRequest(MyLoggingFacade logger, LDAPConfiguration ldap, Collection<String> scopes) {
        super(logger, ldap, scopes);
    }


}
