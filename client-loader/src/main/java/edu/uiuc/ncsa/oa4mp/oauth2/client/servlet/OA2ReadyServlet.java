package edu.uiuc.ncsa.oa4mp.oauth2.client.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.IDTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.*;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.client.ATResponse2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.client.ATServer2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.MyOtherJWTUtil2;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientEnvironment;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.core.util.TokenUtil;
import edu.uiuc.ncsa.security.servlet.JSPUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import net.sf.json.util.JSONUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * A very, very simple (as in stupid) ready servlet. This is the target of the callback uri supplied in
 * the initial request. <br><br>This example is intended to show control flow rather than be a polished application.
 * Feel free to boilerplate from it as needed. Do not deploy this in production environments.
 * <p>Created by Jeff Gaynor<br>
 * <p/>
 * on 2/10/12 at  1:43 PM
 */

public class OA2ReadyServlet extends ClientServlet {
    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        if (request.getParameterMap().containsKey(OA2Constants.ERROR)) {
            throw new OA2GeneralError(request.getParameter(OA2Constants.ERROR),
                    request.getParameter(OA2Constants.ERROR_DESCRIPTION),
                    HttpStatus.SC_BAD_REQUEST,
                    request.getParameter(OA2Constants.STATE));
        }
        // Get the cert itself. The server itself does a redirect using the callback to this servlet
        // (so it is the server that actually is invoking this method after the authorization
        // step.) The token and verifier are peeled off and used
        // to complete the request.
        info("2.a.0 Getting token and verifier.");
        String token = request.getParameter(CONST(ClientEnvironment.TOKEN));
        if(TokenUtil.isBase32(token)){
            token = TokenUtil.b32DecodeToken(token);
        }
        String state = request.getParameter(OA2Constants.STATE);
        if (token == null) {
            warn("2.a.1 The token is " + (token == null ? "null" : token) + ".");
            GeneralException ge = new GeneralException(" This servlet requires parameters for the token and possibly verifier.");
            request.setAttribute("exception", ge);
            JSPUtil.fwd(request, response, getCE().getErrorPagePath());
            return;
        }
        info("2.a.2 Token found.");
        DebugUtil.trace(this, "token = '" + token + "'");
        DebugUtil.trace(this, "state = '" + state + "'");
        OA2ClientEnvironment oa2ce = (OA2ClientEnvironment) getCE();

        AuthorizationGrant grant = new AuthorizationGrantImpl(URI.create(token));
        info("2.a.3 Getting the token from the service");
        String identifier = clearCookie(request, response);
        OA2Asset asset = null;
        if (identifier == null) {
            asset = (OA2Asset) getCE().getAssetStore().getByToken(BasicIdentifier.newID(token));
            if (asset != null) {
                identifier = asset.getIdentifierString();
            }
        }
        AssetResponse assetResponse = null;
        OA2MPService oa2MPService = (OA2MPService) getOA4MPService();
        String rawAT = null;
        AccessToken accessToken;
        UserInfo ui = null;
        boolean getCerts = (oa2ce).getScopes().contains(OA2Scopes.SCOPE_MYPROXY);
        boolean gotCertX = false;
        String certXMessage = null;
        if (identifier == null) {
            // Since this is a demo servlet, we don't blow up if there is no identifier found, just can't save anything.
            String msg = " no cookie found. Cannot save certificates";
            warn(msg);
            debug("No cookie found");
            //if(asset == null) asset = new OA2Asset(BasicIdentifier.newID())
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            accessToken = atResponse2.getAccessToken();
            rawAT = accessToken.getToken(); // save it here since we have it
            ui = oa2MPService.getUserInfo(atResponse2.getAccessToken().toString());
            if (getCerts) {
                try {
                    assetResponse = oa2MPService.getCert(asset, atResponse2);
                } catch (Throwable t) {
                    // Then no cert.
                    getCerts = false;
                }
            }
        } else {
            asset = (OA2Asset) getCE().getAssetStore().get(identifier);
            if (asset.getState() == null || !asset.getState().equals(state)) {
                // Just a note: This is most likely to arise when the server's authorize-init.jsp has been
                // changed or replaced and the hidden field for the state (passed to the form, then passed back
                // and therefore not stored on the server anyplace) is missing.
                warn("The expected state from the server was \"" + asset.getState() + "\", but instead \"" + state + "\" was returned. Transaction aborted.");
                throw new IllegalArgumentException(" The state returned by the server is invalid.");
            }
            ATResponse2 atResponse2 = oa2MPService.getAccessToken(asset, grant);
            accessToken = atResponse2.getAccessToken();
            rawAT = accessToken.getToken(); // save it here since we have it

            //  ui = oa2MPService.getUserInfo(atResponse2.getAccessToken().getToken());
            ui = oa2MPService.getUserInfo(identifier);
            if (getCerts) {
                info("2.b.0 Certs requested, retrieving...");
                try {
                    assetResponse = oa2MPService.getCert(asset, atResponse2);
                } catch (Throwable t) {
                    info("2.b.1 Error getting cert: " + t.getMessage());
                    gotCertX = true;
                    certXMessage = t.getMessage();
                }
            }
            // The general case is to do the call with the identifier if you want the asset store managed.
            //assetResponse = getOA4MPService().getCert(token, null, BasicIdentifier.newID(identifier));
        }
            setATInfo(request, accessToken);

        ServletDebugUtil.trace(this, "show ID token? " + oa2ce.isShowIDToken());
        // Now to display the id token. This only exists if this is an OIDC server, so that is a requirement here.
        if (oa2ce.isOidcEnabled() && oa2ce.isShowIDToken()) {

            ATServer2 atServer2 = (ATServer2) oa2ce.getDelegationService().getAtServer();

            JSONWebKeys jsonWebKeys = atServer2.getJsonWebKeys();
            ServletDebugUtil.trace(this, "JSON webkeys = " + jsonWebKeys);
            // The store is needed in the servlet if the user wants to display
            // the ID token. We will only have the access token later so we have
            // to key off that.
            IDTokenImpl idToken = ATServer2.getIDTokenStore().get(accessToken.getJti());

            setIDTInfo(request, idToken.getToken(), jsonWebKeys);

        } else {
            setIDTInfo(request, null, null); // sets the fields to "(none)"

        }
        setATInfo(request, accessToken);
        // Again, we take the first returned cert to peel off some information to display. This
        // just proves we got a response.

        if (getCerts) {
            if (gotCertX) {
                request.setAttribute("certSubject", "There was a problem getting the cert:" + certXMessage);
            } else {
                if (assetResponse.getX509Certificates() == null) {
                    request.setAttribute("certSubject", "(no cert returned)");
                } else {
                    X509Certificate cert = assetResponse.getX509Certificates()[0];
                    // Rest of this is putting up something for the user to see
                    request.setAttribute("certSubject", cert.getSubjectDN());
                    request.setAttribute("cert", CertUtil.toPEM(assetResponse.getX509Certificates()));
                    request.setAttribute("username", assetResponse.getUsername());
                    // FIX OAUTH-216. Note that this is displayed on the client's success page.
                    if (asset.getPrivateKey() != null) {
                        request.setAttribute("privateKey", KeyUtil.toPKCS1PEM(asset.getPrivateKey()));
                    } else {
                        request.setAttribute("privateKey", "(none)");
                    }
                }
            }

        } else {
            request.setAttribute("certSubject", "(no cert)");
        }
        info("2.b.2 Done! Displaying success page.");

        if (ui != null) {
            String output = JSONUtils.valueToString(ui.toJSon(), 1, 0);
            request.setAttribute("userinfo", output);
        } else {
            request.setAttribute("userinfo", "no user info returned.");
        }
        // Fix in cases where the server request passes through Apache before going to Tomcat.

        String contextPath = request.getContextPath();
        if (!contextPath.endsWith("/")) {
            contextPath = contextPath + "/";
        }
        request.setAttribute("action", contextPath);
        info("2.b.3 Completely finished with delegation.");


        response.setCharacterEncoding("UTF-8");
        logOK( request); // CIL-1722

        JSPUtil.fwd(request, response, getCE().getSuccessPagePath());
        return;
    }

    /**
     * Set the attributes for the id token.
     *
     * @param request
     * @param rawJWT
     * @param jsonWebKeys
     */
    protected void setIDTInfo(HttpServletRequest request, String rawJWT, JSONWebKeys jsonWebKeys) {
        if (rawJWT == null || rawJWT.isEmpty()) {
            request.setAttribute("id_token", "(none)");
        } else {
            String[] atParts = JWTUtil.decat(rawJWT);
            String h = atParts[JWTUtil.HEADER_INDEX];
            JSONObject header = null;

            String p = atParts[JWTUtil.PAYLOAD_INDEX];
            header = JSONObject.fromObject(new String(Base64.decodeBase64(h)));

            JSONObject payload = JSONObject.fromObject(new String(Base64.decodeBase64(p)));
            request.setAttribute("id_token", rawJWT); //token should not be wrapped
            request.setAttribute("id_payload", payload.toString(2));

            request.setAttribute("id_header", header.toString(2));
            JSONWebKey webKey = jsonWebKeys.get(header.get(JWTUtil.KEY_ID));
            String keyPEM = KeyUtil.toX509PEM(webKey.publicKey);
            request.setAttribute("id_public_key", StringUtils.wrap(keyPEM, 80));

        }
    }

    protected void setATInfo(HttpServletRequest request, AccessToken accessToken) {
        info("2.b. Formatting access token.");
        String rawAT = accessToken.getToken();
        if (rawAT == null || rawAT.length() == 0) {
            throw new NFWException(" no access token returned.");
        }

        OA2ClientEnvironment oa2ce = (OA2ClientEnvironment) getEnvironment();
        ATServer2 atServer2 = (ATServer2) oa2ce.getDelegationService().getAtServer();
        JSONWebKeys jsonWebKeys = atServer2.getJsonWebKeys(); // This fetches it from wherever it is

        boolean isVerified = false;
        boolean isSciToken = false;
        try {
            JSONObject scitoken = MyOtherJWTUtil2.verifyAndReadJWT(rawAT, jsonWebKeys);
            request.setAttribute("at_payload", scitoken.toString(2));
            isVerified = true;
            isSciToken = true;
        } catch (Throwable t) {
            request.setAttribute("at_payload", rawAT);
            isSciToken = false;
        }
        if(isSciToken) {
                    int width = 80;

                    request.setAttribute("accessToken", StringUtils.wrap(rawAT, width));
                    String[] atParts = MyOtherJWTUtil2.decat(rawAT);
                    String h = atParts[MyOtherJWTUtil2.HEADER_INDEX];
                    JSONObject header = null;

                    String p = atParts[MyOtherJWTUtil2.PAYLOAD_INDEX];
                    try {
                        header = JSONObject.fromObject(new String(Base64.decodeBase64(h)));
                        request.setAttribute("at_accessToken", rawAT);
                        request.setAttribute("at_accessToken2", StringUtils.wrap(rawAT, width)); // line wrapped version
                        request.setAttribute("at_header", header.toString(2));
                        request.setAttribute("at_verified", Boolean.toString(isVerified));
                        JSONWebKey webKey = jsonWebKeys.get(header.get(JWTUtil.KEY_ID));
                        String keyPEM = KeyUtil.toX509PEM(webKey.publicKey);
                        request.setAttribute("at_public_key", keyPEM);

                    } catch (Throwable t) {
                        getMyLogger().warn("Error decoding header from response", t);
                     //   System.err.println("Returned raw AT=" + rawAT);
                    }
                }else{
                    // The server is not configured to return a SciToken at the first step, so just print this out.
                         request.setAttribute("at_accessToken", rawAT);
                         request.setAttribute("at_accessToken2", StringUtils.wrap(rawAT, 80));
                         request.setAttribute("at_header", "(none)");
                         request.setAttribute("at_verified", "(n/a)");
                         request.setAttribute("at_public_key", "(n/a)");
                }
    }
}
