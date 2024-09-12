package org.oa4mp.server.api.storage.servlet;

import org.oa4mp.delegation.server.OIDCDiscoveryTags;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.request.IssuerResponse;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/12/16 at  1:04 PM
 */
public class DiscoveryServlet extends MyProxyDelegationServlet implements OIDCDiscoveryTags {

   public static  final String DEFAULT_REGISTRATION_ENDPOINT = "oidc-cm";
    public static final String DISCOVERY_PATH = ".well-known";

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        throw new NotImplementedException("Not implemented in discovery");
    }

    public String getDiscoveryPagePath() {
        return discoveryPagePath;
    }

    public void setDiscoveryPagePath(String discoveryPagePath) {
        this.discoveryPagePath = discoveryPagePath;
    }

    protected String discoveryPagePath = "/well-known.jsp";

    protected JSONObject setValues(HttpServletRequest httpServletRequest, JSONObject jsonObject) {
        if (jsonObject == null) {
            jsonObject = new JSONObject();
        }
        String requestURI = getRequestURI(httpServletRequest);
        String authzEndpoint;
        if (!isEmpty(getServiceEnvironment().getAuthorizationServletConfig().getAuthorizationURI())) {
            authzEndpoint = getServiceEnvironment().getAuthorizationServletConfig().getAuthorizationURI();
        } else {
            authzEndpoint = requestURI + "/authorize";
        }
        jsonObject.put(AUTHORIZATION_ENDPOINT, authzEndpoint);
        // The next line points to the native OA4MP registration protocol
        //jsonObject.put(REGISTRATION_ENDPOINT, requestURI + "/register");
        // The next line points to the RFC 7591/7592 protocol.
        // Should be the same as in ClientManagementConstants.DEFAULT_RFC7591_ENDPOINT
        jsonObject.put(REGISTRATION_ENDPOINT, requestURI + "/" + DEFAULT_REGISTRATION_ENDPOINT);
        return jsonObject;
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        JSONObject jsonObject = new JSONObject();
        jsonObject = setValues(httpServletRequest, jsonObject);
        String out = JSONUtils.valueToString(jsonObject, 1, 0);
        httpServletResponse.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter printWriter = httpServletResponse.getWriter();
        printWriter.write(out);
        printWriter.close();
        printWriter.flush();
        //httpServletRequest.setAttribute(DISCOVERY_CONTENT, out);
        //JSPUtil.fwd(httpServletRequest, httpServletResponse, getDiscoveryPagePath());
    }

    protected static String getRequestURI(HttpServletRequest request, boolean includePort) {
        String requestURI = request.getScheme() + "://" + request.getServerName() + (includePort ? (":" + request.getServerPort()) : "") + request.getRequestURI();
        //  String requestURI = request.getRequestURI();
        if (requestURI.endsWith("/")) {
            requestURI = requestURI.substring(0, requestURI.length() - 1);
        }
        if (0 < requestURI.indexOf("/.well-known")) {
            requestURI = requestURI.substring(0, requestURI.indexOf("/.well-known"));
        }
        return requestURI;
    }

    protected static String getRequestURI(HttpServletRequest request) {
        return getRequestURI(request, true);
    }
}
