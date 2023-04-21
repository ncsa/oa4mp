package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ManagerFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.ResponseSerializer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.EnvServlet;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.sql.SQLException;

/**
 * The client management servlet.
 * @deprecated This has been replaced by RFC 7591 and 7592 complient servlet. See {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMServlet}
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  11:41 AM
 */
public class ClientServlet extends EnvServlet {

    @Override
    public void storeUpdates() throws IOException, SQLException {
        if (storeUpdatesDone) return; // run this once
        storeUpdatesDone = true;
        processStoreCheck(getOA2SE().getAdminClientStore());
        processStoreCheck(getOA2SE().getPermissionStore());
    }

    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        throw new NotImplementedException("Get is not supported by this service");
    }

    public ManagerFacade getClientManager() {
        if (clientManager == null) {
            clientManager = new ManagerFacade((OA2SE) getEnvironment());
        }
        return clientManager;
    }

    ManagerFacade clientManager;

    @Override
    public void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        try {
            // The super class rejects anything that does not have an encoding type of
            // application/x-www-form-urlencoded
            // We want this servlet to understand only application/json, so we
            // test for that instead.

            //   printAllParameters(httpServletRequest);
            if (doPing(httpServletRequest, httpServletResponse)) return;
            // TODO Probably should parse the encoding type. 'application/json; charset=UTF-8' would be standard.
            if (!httpServletRequest.getContentType().contains("application/json")) {
                httpServletResponse.setStatus(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE);
                throw new ServletException("Error: Unsupported encoding of \"" + httpServletRequest.getContentType() + "\" for body of POST. Request rejected.");
            }
            doIt(httpServletRequest, httpServletResponse);
            logOK(httpServletRequest); // CIL-1722

        } catch (Throwable t) {
            handleException(new OA2ExceptionHandlerThingie(t, httpServletRequest, httpServletResponse, null));
        }
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        try {
            BufferedReader br = httpServletRequest.getReader();
            DebugUtil.trace(this, "query=" + httpServletRequest.getQueryString());
            StringBuffer stringBuffer = new StringBuffer();
            String line = br.readLine();
            DebugUtil.trace(this, "line=" + line);
            while (line != null) {
                stringBuffer.append(line);
                line = br.readLine();
            }
            br.close();
            if (stringBuffer.length() == 0) {
                throw new IllegalArgumentException("Error: There is no content for this request");
            }
            JSON rawJSON = null;
            try {
                rawJSON = JSONSerializer.toJSON(stringBuffer.toString());
            } catch (Throwable t) {
                throw new IllegalArgumentException("Error: There was a problem parsing the JSON: " + t.getMessage());
            }
            DebugUtil.trace(this, rawJSON.toString());
            if (rawJSON.isArray()) {
                getMyLogger().info("Error: Got a JSON array rather than a request:" + rawJSON);
                throw new IllegalArgumentException("Error: incorrect argument. Not a valid JSON request");
            }
                Response response = getClientManager().process((JSONObject) rawJSON);
                getResponseSerializer().serialize(response, httpServletResponse);
        }catch(Throwable t){
            handleException(new OA2ExceptionHandlerThingie(t, httpServletRequest, httpServletResponse, null));
        }
    }

    protected OA2SE getOA2SE() {
        return (OA2SE) getEnvironment();
    }

    public ResponseSerializer getResponseSerializer() {
        if (responseSerializer == null) {
            responseSerializer = new ResponseSerializer(getOA2SE());
        }
        return responseSerializer;
    }

    ResponseSerializer responseSerializer = null;


}
