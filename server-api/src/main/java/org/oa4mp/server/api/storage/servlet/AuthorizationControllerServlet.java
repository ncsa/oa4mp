package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.request.IssuerResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/14 at  10:47 AM
 */
public class AuthorizationControllerServlet extends OA4MPServlet {
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
