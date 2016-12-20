package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandlerFactory;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandlerFactoryRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/16/16 at  3:08 PM
 */
public class LDAPScopeHandlerFactory extends ScopeHandlerFactory {

    public LDAPScopeHandlerFactory() {
    }

    @Override
    public ScopeHandler create(ScopeHandlerFactoryRequest request) {
        if (request instanceof LDAPScopeHandlerFactoryRequest) {
            LDAPScopeHandlerFactoryRequest req = (LDAPScopeHandlerFactoryRequest) request;
            LDAPScopeHandler h = new LDAPScopeHandler(req.getLdapConfiguration(), req.getLogger());
            h.setScopes(req.getScopes());
            return h;
        }
        BasicScopeHandler h = new BasicScopeHandler();
        h.setScopes(request.getScopes());
        return h;
    }

}
