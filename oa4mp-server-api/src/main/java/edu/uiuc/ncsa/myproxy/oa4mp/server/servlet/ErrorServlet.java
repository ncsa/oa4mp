package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import org.apache.commons.codec.binary.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * This servlet handles error redirects. If an error (such as a 404, 500 or anything else) occurs,
 * OAuth will intecept the response and throw an exception -- losing any other information.
 * Therefore, there must be a redirect and clients must be prepared to deal with these.
 * Generally there are a few error type pages
 * <p>Created by Jeff Gaynor<br>
 * on 9/4/12 at  6:03 PM
 */
public class ErrorServlet extends MyProxyDelegationServlet {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    public static final String MESSAGE = "message";
    public static final String IDENTIFIER = "identifier";
    public static final String STACK_TRACE = "stackTrace";
    public static final String CAUSE = "cause";

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String cause = request.getParameter(CAUSE);
        String identifier = request.getParameter(IDENTIFIER);

        request.setAttribute(CAUSE, cause);
        request.setAttribute(IDENTIFIER, identifier);
        request.setAttribute(MESSAGE, URLDecoder.decode(request.getParameter(MESSAGE), "UTF-8"));
        String stackTrace = request.getParameter(STACK_TRACE);
        if (stackTrace == null || stackTrace.length() == 0) {
            stackTrace = "(none)";
        } else {
            try {
                stackTrace = new String(Base64.decodeBase64(stackTrace));
            } catch (Throwable x) {
                info("Could not decode stack trace for cause " + x.getClass().getName() + " msg=\"" + x.getMessage() + "\", trace:" + stackTrace);
                stackTrace = "(none)";
            }
        }
        request.setAttribute(STACK_TRACE, stackTrace);
        if (cause.equals(UnknownClientException.class.getSimpleName())) {
            JSPUtil.fwd(request, response, "/noClientErrorPage.jsp");
            return;
        }
        Client client = getClient(BasicIdentifier.newID(identifier));
        request.setAttribute("client", client);
        JSPUtil.fwd(request, response, "/errorPage2.jsp");

    }
}
