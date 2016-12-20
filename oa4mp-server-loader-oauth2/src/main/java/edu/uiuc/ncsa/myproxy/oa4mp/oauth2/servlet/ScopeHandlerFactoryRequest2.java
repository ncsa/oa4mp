package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/16/16 at  3:47 PM
 */
public class ScopeHandlerFactoryRequest2 {
    Collection<String> scopes;
    MyLoggingFacade logger;
    OA2SE oa2SE;

    public ScopeHandlerFactoryRequest2(OA2SE oa2SE, Collection<String> scopes) {
        this.oa2SE = oa2SE;
        this.scopes = scopes;
    }

    public ScopeHandlerFactoryRequest2(MyLoggingFacade logger, Collection<String> scopes) {
        this.logger = logger;
        this.oa2SE = oa2SE;
        this.scopes = scopes;
    }
}
