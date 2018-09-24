package edu.uiuc.ncsa.oa4mp.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/15 at  1:16 PM
 */
public class OA2ClientExceptionHandler extends ClientExceptionHandler {

    public OA2ClientExceptionHandler(ClientServlet clientServlet, MyLoggingFacade myLogger) {
        super(clientServlet, myLogger);
    }

    @Override
    public void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (t instanceof OA2RedirectableError) {
            getLogger().info("get a standard error with a redirect");
            OA2RedirectableError oa2RedirectableError = (OA2RedirectableError) t;
            request.setAttribute(OA2Constants.ERROR, oa2RedirectableError.getError());
            request.setAttribute(OA2Constants.ERROR_DESCRIPTION, oa2RedirectableError.getDescription());
            request.setAttribute(OA2Constants.STATE, oa2RedirectableError.getState());
        } else if (t instanceof ServiceClientHTTPException) {
            // This can be thrown by the service client when a bad response comes back from the server.
            // If there really is server problem, this tries to get a human readable error page.
            // parse the body. It should be of the form
            // error=....
            // error_description=...
            // separated by a line feed.
            ServiceClientHTTPException tt = (ServiceClientHTTPException) t;
            getLogger().info("got standard error with http status code = " + tt.getStatus());

            if (!tt.hasContent()) {
                // can't do anything
                defaultSCXresponse(tt, request);
            } else {
                try {
                    parseContent(tt.getContent(), request);
                } catch (GeneralException xx) {
                    defaultSCXresponse(tt, request);
                }
            }
        } else {
            // fall through. We got some exception from someplace and have to manage it.
            // This is really last ditch.
            getLogger().info("Got exception of type " + t.getClass().getSimpleName());
            t.printStackTrace(); // again, something is wrong, possibly with the configuration so more info is better.
            request.setAttribute(OA2Constants.ERROR, t.getClass().getSimpleName());
            request.setAttribute(OA2Constants.ERROR_DESCRIPTION, t.getMessage());
        }

        request.setAttribute("action", getNormalizedContextPath());  // sets return action on error page to this web app.
        JSPUtil.fwd(request, response, clientServlet.getCE().getErrorPagePath());
    }

    /**
     * This will parse the standard error reponse from an OIDC server.
     *
     * @param content
     * @param request
     * @return
     */
    protected void parseContent(String content, HttpServletRequest request) {
        // This will take the payload and parse it as follows. The assumption is that it is of the form
        // X0=Y0
        // X1=Y1
        // X2=Y2
        // etc. where X's are standard OIDB error indicators (e.g. error_description, state) and Y's are the value
        // These are set in the response as attributes, so there is no limit on them.
        boolean hasValidContent = false;
        StringTokenizer st = new StringTokenizer(content, "\n");
        while (st.hasMoreElements()) {
            String currentLine = st.nextToken();
            StringTokenizer clST = new StringTokenizer(currentLine, "=");
            if (!clST.hasMoreTokens() || clST.countTokens() != 2) {
                continue;
            }
            try {
                request.setAttribute(clST.nextToken(), URLDecoder.decode(clST.nextToken(), "UTF-8"));
            } catch (UnsupportedEncodingException xx) {
                // ok, try it without decoding it. (This case should never really happen)
                request.setAttribute(clST.nextToken(), clST.nextToken());
            }
            hasValidContent = true;
        }
        if (!hasValidContent) {
            getLogger().warn("Body or error was not parseable");
            throw new GeneralException();
        }
    }

    /**
     * Used in cases the response from the server cannot be parsed.
     *
     * @param tt
     * @param request
     */
    protected void defaultSCXresponse(ServiceClientHTTPException tt, HttpServletRequest request) {
        request.setAttribute(OA2Constants.ERROR, tt.getClass().getSimpleName());
        request.setAttribute(OA2Constants.ERROR_DESCRIPTION, "Status code=" + tt.getStatus() + ", message=\"" + tt.getMessage() + "\"");
        request.setAttribute(OA2Constants.STATE, "(none)");

    }
}
