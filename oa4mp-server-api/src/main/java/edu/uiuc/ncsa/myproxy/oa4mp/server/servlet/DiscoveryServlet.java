package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/12/16 at  1:04 PM
 */
public class DiscoveryServlet extends MyProxyDelegationServlet {

    public static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    public static final String REGISTRATION_ENDPOINT = "registration_endpoint";
    public static final String DISCOVERY_CONTENT = "content";

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

    protected JSONObject setValues(JSONObject jsonObject) {
        if (jsonObject == null) {
            jsonObject = new JSONObject();
        }
        jsonObject.put(AUTHORIZATION_ENDPOINT, "authorize");
        jsonObject.put(REGISTRATION_ENDPOINT, "register");
        return jsonObject;
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        JSONObject jsonObject = new JSONObject();
        jsonObject = setValues(jsonObject);
        String out = JSONUtils.valueToString(jsonObject, 1, 0);

        httpServletRequest.setAttribute(DISCOVERY_CONTENT, out);
        JSPUtil.fwd(httpServletRequest, httpServletResponse, getDiscoveryPagePath());
    }

}
