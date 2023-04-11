package edu.uiuc.ncsa.myproxy.oa4mp.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientLoaderInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;

/**
 * Basic Client servlet. it has the machinery in it for reading in a configuration file,
 * setting up the {@link edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment} and making the {@link OA4MPService}
 * instance. It also includes a utility call for getting a cookie with
 * the identifier (stored with the key {@value #OA4MP_CLIENT_REQUEST_ID} in
 * the users browser).       <br><br>
 * Look at the two sample uses of this in {@link edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.sample.SimpleStartRequest}
 * and {@link edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.sample.SimpleReadyServlet} to see how to extend and use it.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/12 at  12:51 PM
 */
public abstract class ClientServlet extends AbstractServlet {
    public static final String ACTION_KEY = "actionKey";
    public static final String ACTION_REDIRECT_VALUE = "redirect";
    public static final String REDIR = "redirect";

    HashMap<String, Asset> assetCache;

    protected HashMap<String, Asset> getAssetCache() {
        if (assetCache == null) {
            assetCache = new HashMap<>();
        }
        return assetCache;
    }

    /**
     * If a client specifically requests a response with debugging information then this will
     * be returned ONLY in cases of an error on the server. It is up to the client to unpack this.
     * To use this, add the key to the request with a value of true.
     */
    // quick note -- the client request id is the name of the cookie, which must be RFC 2109 compliant.
    // Don't change the value unless you are careful about this, since tomcat will store a cookie with an
    // improper name but can't retrieve it!
    public static final String OA4MP_CLIENT_REQUEST_ID = "oa4mp_client_req_id";
    public static Cleanup<Identifier, Asset> assetCleanup;


    /**
     * Convenience for client servlets. Does the cast automatically
     *
     * @return
     */
    public ClientEnvironment getCE() {
        return (ClientEnvironment) getEnvironment();
    }


    @Override
    public void loadEnvironment() throws IOException {
        environment = getConfigurationLoader().load();
        oa4mpService = ((ClientLoaderInterface) getConfigurationLoader()).getServiceProvider().get();
    }


    @Override
    public void destroy() {
        super.destroy();
        shutdownCleanup(assetCleanup);
    }

    protected void shutdownCleanup(Cleanup c) {
        if (c != null && !c.isStopThread()) {
            c.setStopThread(true); // Just in case...
            c.interrupt();
        }
    }

    static OA4MPService oa4mpService;


    public OA4MPService getOA4MPService() throws IOException {
        return oa4mpService;
    }

    /**
     * Clear the CILogon client cookie. This way if there is an error the user won't get a
     * stale one with a possible server-side exception later.
     * <br><br> This clears the client request id cookie ({@value #OA4MP_CLIENT_REQUEST_ID}) and returns the currently set value for it.
     * This
     *
     * @param request
     * @param response
     */
    protected String clearCookie(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String identifier = null;
        if (cookies != null) {
            // if there are no cookies (usually because the user surfed into a random page) then
            // exit gracefully rather than just giving some big null pointer stack trace.
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(OA4MP_CLIENT_REQUEST_ID)) {
                    identifier = cookie.getValue();
                    // This removes the cookie since we are done with it.
                    // This way if the user surfs to another portal there won't
                    // be a cookie clash.
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }

        return identifier;
    }

}
