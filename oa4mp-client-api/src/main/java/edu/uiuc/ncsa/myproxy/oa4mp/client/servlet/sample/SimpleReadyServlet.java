package edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.sample;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.cert.X509Certificate;

/**
 * A very, very simple (as in stupid) ready servlet. This is the target of the callback uri supplied in
 * the initial request. <br><br>This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * <p/>
 * on 2/10/12 at  1:43 PM
 */

public class SimpleReadyServlet extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Get the cert itself. The server itself does a redirect using the callback to this servlet
        // (so it is the portal that actually is invoking this method after the authorization
        // step.) The token and verifier are peeled off and used
        // to complete the request.
        info("2.a. Getting token and verifier.");
        String token = request.getParameter(CONST(ClientEnvironment.TOKEN));
        String verifier = request.getParameter(CONST(ClientEnvironment.VERIFIER));
        if (token == null && verifier == null) {
            warn("2.a. The token is " + (token == null ? "null" : token) + " and the verifier is " + (verifier == null ? "null" : verifier));
            GeneralException ge = new GeneralException("Error: This servlet requires parameters for the token and possibly verifier.");
            request.setAttribute("exception", ge);
            JSPUtil.fwd(request, response, getCE().getErrorPagePath());
            return;
        }
        info("2.a Token found.");

        info("2.a. Getting the cert(s) from the service");
        String identifier = clearCookie(request, response);
        if(identifier == null){
            Asset asset =  getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if(asset != null){
                identifier = asset.getIdentifierString();
            }
        }
        AssetResponse assetResponse = null;
        if (identifier == null) {
            // Since this is a demo servlet, we don't blow up if there is no identifier found, just can't save anything.
            String msg = "Error: no cookie found. Cannot save certificates";
            warn(msg);
            debug("No cookie found");
            assetResponse = getOA4MPService().getCert(token, verifier);
        } else {
            // The general case is to do the call with the identifier if you want the asset store managed.
            assetResponse = getOA4MPService().getCert(token, verifier, BasicIdentifier.newID(identifier));
        }
        // The work in this call

        // Again, we take the first returned cert to peel off some information to display. This
        // just proves we got a response.
        X509Certificate cert = assetResponse.getX509Certificates()[0];

        info("2.b. Done! Displaying success page.");

        // Rest of this is putting up something for the user to see
        request.setAttribute("certSubject", cert.getSubjectDN());
        request.setAttribute("cert", CertUtil.toPEM(assetResponse.getX509Certificates()));
        request.setAttribute("username", assetResponse.getUsername());
        // Fix in cases where the server request passes through Apache before going to Tomcat.

        String contextPath = request.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath = contextPath + "/";
        }
        request.setAttribute("action", contextPath);
        info("2.a. Completely finished with delegation.");
        JSPUtil.fwd(request, response, getCE().getSuccessPagePath());
        return;
    }
}
