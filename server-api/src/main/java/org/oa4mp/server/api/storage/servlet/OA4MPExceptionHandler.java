package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTimestampException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.HostUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.oa4mp.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.ExceptionHandlerThingie;
import edu.uiuc.ncsa.security.servlet.JSPUtil;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.ProtocolException;
import java.net.UnknownHostException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/15 at  4:56 PM
 */
public class OA4MPExceptionHandler implements ExceptionHandler {
    MyLoggingFacade logger;

    @Override
    public MyLoggingFacade getLogger() {
        return logger;
    }

    public OA4MPExceptionHandler(MyLoggingFacade logger) {
        this.logger = logger;
    }

    @Override
    public void handleException(ExceptionHandlerThingie xh) throws IOException, ServletException {
        Throwable t = xh.throwable;
        HttpServletRequest request = xh.request;
        HttpServletResponse response = xh.response;

        if ((t instanceof NullPointerException)) {
            getLogger().error("Null pointer", t);
            throw new GeneralException("Error: Null pointer encountered.");
        }
        // these get kicked back to the client asap, since we can't really say much else.
        if ((t instanceof UnknownClientException) || t instanceof UnapprovedClientException) {
            throw (GeneralException) t;
        }
        if (t instanceof InvalidTimestampException) {
            // Fix for OAUTH-173: improved error message on timeout.
            request.setAttribute("message", "Session expired. Please try again.");
            request.setAttribute("exception", (t.getCause() == null) ? t : t.getCause());
        } else {
            request.setAttribute("message", ((t.getCause() == null) ? t.getMessage() : t.getCause().getMessage()) + "\n");
            request.setAttribute("exception", (t.getCause() == null) ? t : t.getCause());
        }
        request.setAttribute("clientIP", request.getRemoteAddr() + "\n");
        try {
            request.setAttribute("clientHost", HostUtil.reverseLookup(request.getRemoteAddr()) + "\n");
        } catch (UnknownHostException ux) {
            request.setAttribute("clientHost", "could not resolve client IP to a host\n");
        }
        if (t.getCause() != null) {
            if ((t.getCause() instanceof FailedLoginException) || (t.getCause() instanceof LoginException)) {
                JSPUtil.fwd(request, response, "/failedLogin.jsp");
                return;
            }
            if (t.getCause() instanceof ProtocolException) {
                JSPUtil.fwd(request, response, "/failedLogin.jsp");
                return;
            }
        }
//              }

        // default case.
        // This ensures that the proper message is displayed.
        JSPUtil.fwd(request, response, "/oops.jsp");
    }
}
