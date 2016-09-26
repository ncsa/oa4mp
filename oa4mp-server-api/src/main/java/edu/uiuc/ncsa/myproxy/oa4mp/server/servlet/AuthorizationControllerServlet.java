package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/14 at  10:47 AM
 */
public class AuthorizationControllerServlet extends MyProxyDelegationServlet {
    public static AuthorizationHandler getAuthorizationHandler() {
        return authorizationHandler;
    }

    public static void setAuthorizationHandler(AuthorizationHandler authorizationHandler) {
        AuthorizationControllerServlet.authorizationHandler = authorizationHandler;
    }

    static AuthorizationHandler authorizationHandler = null;


    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        throw new NotImplementedException("Error: This method is not implemented.");
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
         getAuthorizationHandler().doIt(request,response);
    }
}
