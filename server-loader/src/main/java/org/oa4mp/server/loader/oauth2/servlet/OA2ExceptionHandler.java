package org.oa4mp.server.loader.oauth2.servlet;

import edu.uiuc.ncsa.security.core.exceptions.MissingContentException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.ExceptionHandlerThingie;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.server.*;
import org.oa4mp.server.api.storage.servlet.AbstractAuthenticationServlet;
import org.oa4mp.server.loader.oauth2.claims.LDAPException;
import org.qdl_lang.exceptions.QDLException;
import org.qdl_lang.exceptions.QDLExceptionWithTrace;

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

    protected void warn(String x) {
        if (getLogger() != null) {
            getLogger().warn(x);
        } else {
            System.err.println(x); // really bad, but not a lot we can do.
        }
    }
    protected void info(String x) {
        if (getLogger() != null) {
            getLogger().info(x);
        }else{
            System.err.println(x); // Just awful
        }
    }

    protected void error(String x) {
        if (getLogger() != null) {
            getLogger().error(x);
        } else {
            System.err.println(x); // Just awful, definitely killed the flow.
        }
    }

    @Override
    public void handleException(ExceptionHandlerThingie xh) throws IOException, ServletException {
        Throwable t = xh.throwable;
        HttpServletRequest request = xh.request;
        HttpServletResponse response = xh.response;
        BaseClient baseClient = null;
        String forensicMessage = null;
        if (t instanceof OA2GeneralError) {
            OA2GeneralError ge =(OA2GeneralError) t;
            if (ge.hasClient()) {
                baseClient = ge.getClient();
            }
            if(ge.hasForensicMessage()){
                forensicMessage = ge.getForensicMessage();
            }
        } else {
            if ((xh instanceof OA2ExceptionHandlerThingie) && ((OA2ExceptionHandlerThingie) xh).hasClient()) {
                baseClient = ((OA2ExceptionHandlerThingie) xh).client;
            }
        }
        // Do QDL. If there is a script, print out the stack trace
        if (t instanceof QDLException) {
            QDLException qx = (QDLException) t;
            if (qx.getCause() != null) {
                t = qx.getCause();
            }
                if(qx instanceof QDLExceptionWithTrace){
                    QDLExceptionWithTrace qxTrace = (QDLExceptionWithTrace) qx;
                    if(qxTrace.isScript()){
                        forensicMessage = "QDL script stack trace:\n" + qxTrace.stackTrace();
                    }else{
                        forensicMessage = "No QDL script"; // So it was a code block
                    }
                }
        }
        String message = "";
        if (baseClient != null) {
            message = "[" + baseClient.getIdentifierString() + "]";
        }
        String address = AbstractServlet.getRequestIPAddress(xh.request);
        message = message + "<" + address + ">";

        if(forensicMessage== null){
            message = message + " error: " + t.getMessage();
            warn(message); // Fixes CIL-1722
        }else{
            message = message + "\n\tclient id : " + (baseClient==null?"unknown":baseClient.getIdentifierString());
            message = message + "\n\t    error : " + t.getMessage();
            message = message + "\n\t  message : " + forensicMessage;
            warn(message); // Fixes CIL-1722
        }
        if (t == null) {
            // really messed up, should never ever happen
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "Internal error", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
        }
        if (t instanceof MissingContentException) {
            // CIL-1582
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, t.getMessage(), HttpStatus.SC_BAD_REQUEST, null);
        }
        if (t instanceof LDAPException) {
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "LDAP error", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
        }
        if ((t instanceof NullPointerException) || (t.getCause()!=null && t.getCause() instanceof NullPointerException)) {
            getLogger().error("Null pointer", t); // *should* log it with the stack trace
            t.printStackTrace();
            t = new OA2GeneralError(OA2Errors.SERVER_ERROR, "Null pointer", HttpStatus.SC_INTERNAL_SERVER_ERROR, null);
        }

        if (t instanceof ExceptionWrapper) {
            // In this case we are getting this as a response after a forward to another servlet and have to unpack it.
            t = t.getCause();
        }


        // If there is really a servlet exception (defined as a bonafide unrecoverable state, like storage is down or
        // no client_id, e.g.) then pass back the servlet exception and let the container handle it. At some point we might just
        // want to have a pretty page for this.
        if (t instanceof ServletException) {
            response.setStatus(500);
            throw (ServletException) t;
        }

        // We explictly force where these are evaluated.
        if (t instanceof OA2JSONException) {
            handleOA2Error((OA2JSONException) t, response);
            return;
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
        oa2GeneralError.printStackTrace();
        if(oa2GeneralError.getCause()  !=null ){
            oa2GeneralError.getCause().printStackTrace();
        }
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

    protected void handleOA2Error(OA2JSONException jsonException, HttpServletResponse response) throws IOException {
        response.setStatus(jsonException.getHttpStatus());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        writer.write(jsonException.toJSON().toString());
        writer.flush();
        writer.close();
    }

    // Fix for CIL-332: This should now send JSON with the correct http status.
    // Also note, that according to the spec (section 5.2) there is never a redirect to
    // the error endpoint. The body of the response is JSON.
    protected void handleOA2Error(OA2ATException oa2ATException, HttpServletResponse response) throws IOException {
        response.setStatus(oa2ATException.getHttpStatus());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter writer = response.getWriter();
        writer.write(oa2ATException.toJSON().toString());
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
        AbstractAuthenticationServlet.MyHttpServletResponseWrapper wrapper = null;
        if (response instanceof AbstractAuthenticationServlet.MyHttpServletResponseWrapper) {
            wrapper = (AbstractAuthenticationServlet.MyHttpServletResponseWrapper) response;
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
