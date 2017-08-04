package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandlerFactory;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandlerFactoryRequest;

import java.util.LinkedList;

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

    /**
     * This creates a uniform list of scope handlers for both the access token servlet and the user info servlet.
     * It will use a common handler if there is one and use the configured factory to create appropriate ones
     * (and populate them with the right runtime environment otherwise.
     * @param oa2SE
     * @param client
     * @return
     */
    public static LinkedList<ScopeHandler> createScopeHandlers(OA2SE oa2SE, OA2Client client) {
        DebugUtil.dbg(LDAPScopeHandlerFactory.class, "Starting to create LDAPScopeHandlers per client");
             LinkedList<ScopeHandler> scopeHandlers = new LinkedList<>();

             if (client.getLdaps()==null || client.getLdaps().isEmpty()) {
                 DebugUtil.dbg(LDAPScopeHandlerFactory.class, "using default scope handler=");
                 if(oa2SE.getScopeHandler() instanceof BasicScopeHandler){
                     BasicScopeHandler bb = (BasicScopeHandler)oa2SE.getScopeHandler();
                     if(bb.getOa2SE() == null){
                         DebugUtil.dbg(LDAPScopeHandlerFactory.class,"setting scope handler environment #1");
                         bb.setOa2SE(oa2SE);
                     }
                 }
                 scopeHandlers.add(oa2SE.getScopeHandler());
             } else {
                 for (LDAPConfiguration cfg : client.getLdaps()) {
                     DebugUtil.dbg(LDAPScopeHandlerFactory.class,"Got LDAP configuration for server " + cfg.getServer());
                     LDAPScopeHandlerFactoryRequest req = new LDAPScopeHandlerFactoryRequest(oa2SE.getMyLogger(),
                             cfg, client.getScopes());
                     ScopeHandler scopeHandler = ScopeHandlerFactory.newInstance(req);
                     if(scopeHandler instanceof BasicScopeHandler){
                         DebugUtil.dbg(LDAPScopeHandlerFactory.class, "Scope handler\"" + scopeHandler.getClass().getSimpleName() + "\" is configured.");

                         ((BasicScopeHandler)scopeHandler).setOa2SE(oa2SE);
                         DebugUtil.dbg(LDAPScopeHandlerFactory.class, "setting scope handler environment #2");
                     }
                     scopeHandlers.add(scopeHandler);
                 }
             }
             return scopeHandlers;
         }

}
