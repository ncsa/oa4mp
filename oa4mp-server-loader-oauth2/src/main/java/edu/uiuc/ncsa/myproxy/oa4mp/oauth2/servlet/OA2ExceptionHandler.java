package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.LDAPException;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.*;
import edu.uiuc.ncsa.oa4mp.delegation.server.ExceptionWrapper;
import edu.uiuc.ncsa.oa4mp.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.qdl.exceptions.QDLExceptionWithTrace;
import edu.uiuc.ncsa.security.core.exceptions.MissingContentException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/15 at  3:16 PM
 */
public class OA2ExceptionHandler implements ExceptionHandler {
    MyLoggingFacade logger;

    @Override
    public MyLoggingFacade getLogger() {
        return logger;
    }

    public OA2ExceptionHandler(MyLoggingFacade logger) {
        this.logger = logger;
    }

    @Override
    public void handleException(Throwable t, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
   //     ServletDebugUtil.trace(this, "Error", t);
        if (t instanceof QDLExceptionWithTrace) {
            if (t.getCause() != null) {
                t = t.getCause();
            }

        }

        if(t instanceof MissingContentException){
            // CIL-1582
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, t.getMessage(), HttpStatus.SC_BAD_REQUEST, null);
        }
        if (t instanceof LDAPException) {
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "LDAP error", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
        }
        if ((t instanceof NullPointerException)) {
            getLogger().error("Null pointer", t);
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "Null pointer", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
        }

        if (t instanceof ExceptionWrapper) {
            // In this case we are getting this as a response after a forward to another servlet and have to unpack it.
            t = t.getCause();
        }

        if (t == null) {
            // really messed up, should never ever happen
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "Internal error", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
        }
        // If there is really a servlet exception (defined as a bonafide unrecoverable state, like storage is down or
        // no client_id, e.g.) then pass back the servlet exception and let the container handle it. At some point we might just
        // want to have a pretty page for this.
        if (t instanceof ServletException) {
            response.setStatus(500);
            throw (ServletException) t;
        }


        if (t instanceof OA2ATException) {
            handleOA2Error((OA2ATException) t, response);
            return;
        }
        if (t instanceof OA2RedirectableError) {
            handleOA2Error((OA2RedirectableError) t, response);
            return;
        }
        if (t instanceof OA2GeneralError) {
            handleOA2Error((OA2GeneralError) t, response);
            return;
        }
        // The next couple of exceptions can be thrown when there is no client (so the callback uri cannot be verified)
        if ((t instanceof UnknownClientException) || (t instanceof UnapprovedClientException)) {
            handleOA2Error(
                    new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT
                            , "unknown client",
                            HttpStatus.SC_BAD_REQUEST, null), response);
            return;
        }
        // This handles every other type of exception.
        handleOA2Error(new OA2GeneralError(OA2Errors.SERVER_ERROR, t.getMessage(), HttpStatus.SC_INTERNAL_SERVER_ERROR, null), response);
    }

    protected String encode(String x) throws UnsupportedEncodingException {
        if (x == null) {
            return "";
        }
        return URLEncoder.encode(x, "UTF-8");
    }

    protected void handleOA2Error(OA2GeneralError oa2GeneralError, HttpServletResponse response) throws IOException {
        DebugUtil.trace(this, "error = " + oa2GeneralError);
        PrintWriter writer = response.getWriter();
        response.setStatus(oa2GeneralError.getHttpStatus());
        writer.println(OA2Constants.ERROR + "=\"" + encode(oa2GeneralError.getError()) + "\"");
        writer.println(OA2Constants.ERROR_DESCRIPTION + "=\"" + encode(oa2GeneralError.getDescription()) + "\"");
        if (oa2GeneralError.getState() != null) {
            writer.println(OA2Constants.STATE + "=\"" + encode(oa2GeneralError.getState()) + "\"");
        }
        writer.flush();
        writer.close();
    }

    // Fix for CIL-332: This should now send JSON with the correct http status.
    // Also note, that according to the spec (section 5.2) there is never a redirect to
    // the error endpoint. The body of the response is JSON.
    protected void handleOA2Error(OA2ATException oa2ATException, HttpServletResponse response) throws IOException {
        response.setStatus(oa2ATException.getHttpStatus());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(OA2Constants.ERROR, oa2ATException.getError());
        jsonObject.put(OA2Constants.ERROR_DESCRIPTION, oa2ATException.getDescription());
        if(oa2ATException.getErrorURI() != null){
            jsonObject.put(OA2Constants.ERROR_URI, oa2ATException.getErrorURI().toString());
        }
        if (oa2ATException.getState() != null) {
            // not quite the spec., but clients may need this.
            jsonObject.put(OA2Constants.STATE, oa2ATException.getState());
        }

        PrintWriter writer = response.getWriter();

        writer.write(jsonObject.toString());
        writer.flush();
        writer.close();
    }

    protected void handleOA2Error(OA2RedirectableError oa2RedirectableError, HttpServletResponse response) throws IOException {
        // Fixes OAUTH-174, better handling of errors on the server side, making it all spec. compliant.
        if (oa2RedirectableError.getCallback() == null) {
            // Except here, since there is no callback possible if it is not included in the first place.
            // Convert to a general error
            handleOA2Error(new OA2GeneralError(oa2RedirectableError), response);
            return;
        }
        // Check is the response has been wrapped in a helper class and do a wee bit of management on said class.
        AbstractAuthorizationServlet.MyHttpServletResponseWrapper wrapper = null;
        if (response instanceof AbstractAuthorizationServlet.MyHttpServletResponseWrapper) {
            wrapper = (AbstractAuthorizationServlet.MyHttpServletResponseWrapper) response;
            // set this so that other components know a redirect occurred and can handle that themselves (usually by just returning).
            wrapper.setExceptionEncountered(true);
        }
        String cb = oa2RedirectableError.getCallback().toString();
        boolean hasQM = (0 < cb.indexOf("?")); // CIL-407 FIX
        cb = cb + (hasQM ? "&" : "?") + OA2Constants.ERROR + "=" + oa2RedirectableError.getError() + "&" +
                URLEncoder.encode(OA2Constants.ERROR_DESCRIPTION, "UTF-8") + "=" +
                URLEncoder.encode(oa2RedirectableError.getDescription(), "UTF-8");
        //CIL-312 fix.
        String state = oa2RedirectableError.getState();
        state = state == null ? "" : state;
        cb = cb + "&" + OA2Constants.STATE + "=" + URLEncoder.encode(state, "UTF-8");

        // It is possible that there is no state, in which case, the state variable will be null and you will get and NPE
        // from the encoder. Return empty state if there was none.
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
        response.sendRedirect(cb);
        return;
    }
}
