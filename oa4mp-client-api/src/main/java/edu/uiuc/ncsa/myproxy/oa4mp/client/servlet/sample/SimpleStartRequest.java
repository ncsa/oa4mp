package edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.sample;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A simple servlet that starts the request. It will make the initial request and set an identifier
 * cookie in the users browser. If there is an {@link AssetStore} configured, it will make
 * an entry for the {@link Asset} resulting from this delegation.
 * <br><br>
 * This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/12 at  10:24 AM
 */
public class SimpleStartRequest extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        info("1.a. Starting transaction");
        OA4MPResponse gtwResp = null;
        // Drumroll please: here is the work for this call.
        Identifier id = AssetStoreUtil.createID();
        gtwResp = getOA4MPService().requestCert(id);

        // if there is a store, store something in it.
        Cookie cookie = new Cookie(OA4MP_CLIENT_REQUEST_ID, id.getUri().toString());
        cookie.setMaxAge(15 * 60); // 15 minutes
        cookie.setSecure(true);
        debug("id = " + id.getUri());
        response.addCookie(cookie);
        info("1.b. Got response. Creating page with redirect for " + gtwResp.getRedirect().getHost());
        if (getCE().isShowRedirectPage()) {
            request.setAttribute(REDIR, REDIR);
            request.setAttribute("redirectUrl", gtwResp.getRedirect().toString());
            request.setAttribute("privateKey", KeyUtil.toPKCS8PEM(gtwResp.getPrivateKey()));
            request.setAttribute(ACTION_KEY, ACTION_KEY);
            request.setAttribute("action", ACTION_REDIRECT_VALUE);

            // Normally, we'd just do a redirect, but we will put up a page and show the redirect to the user.
            // The client response contains the generated private key as well. It is a very bad idea to show the
            // private key anywhere.
            // This is a sample application -- all we need to do to complete the process is send along the redirect url.

            info("1.b. Showing redirect page.");
            JSPUtil.fwd(request, response, getCE().getRedirectPagePath());
            //response.sendRedirect(getServletContext().getContextPath() + getCE().getRedirectPagePath());

            return;
        }
        response.sendRedirect(gtwResp.getRedirect().toString());
    }

}
