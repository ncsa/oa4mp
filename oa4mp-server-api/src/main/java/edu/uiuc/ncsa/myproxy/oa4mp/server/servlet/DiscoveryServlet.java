package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
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
public class DiscoveryServlet extends MyProxyDelegationServlet {

    public static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    public static final String REGISTRATION_ENDPOINT = "registration_endpoint";
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
        if(!isEmpty(getServiceEnvironment().getAuthorizationServletConfig().getAuthorizationURI())){
            jsonObject.put(AUTHORIZATION_ENDPOINT, getServiceEnvironment().getAuthorizationServletConfig().getAuthorizationURI());
        }else{
            jsonObject.put(AUTHORIZATION_ENDPOINT, requestURI + "/authorize");
        }
        jsonObject.put(REGISTRATION_ENDPOINT, requestURI + "/register");
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
    protected String getRequestURI(HttpServletRequest request) {
        String requestURI =   request.getScheme() + "://" + request.getServerName() +":"+ request.getServerPort() + "/" + request.getRequestURI();
        if (requestURI.endsWith("/")) {
            requestURI = requestURI.substring(0, requestURI.length() - 1);
        }
        if(0 < requestURI.indexOf("/.well-known")){
            requestURI = requestURI.substring(0,requestURI.indexOf("/.well-known"));
        }
        return requestURI;
    }
}
