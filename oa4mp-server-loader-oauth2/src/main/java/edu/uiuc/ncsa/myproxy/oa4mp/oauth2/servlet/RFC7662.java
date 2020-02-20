package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The token introspection servlet
 * This implements <a href="https://tools.ietf.org/html/rfc7662">RFC7662</a>
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/20 at  2:10 PM
 */
public class RFC7662 extends TokenManagerServlet {

    @Override
    protected void doIt(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment().getTransactionStore();

        OA2Client client = verifyClient(req, "Bearer");

        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);
        if (!tokenTypeHint.equals(TYPE_ACCESS_TOKEN) || !tokenTypeHint.equals(TYPE_REFRESH_TOKEN)) {
            // as per spec, throw the only exception this servlet is allowed
            new OA2GeneralError("unsupported_token_type", "The token type of \"" + tokenTypeHint + "\" is not supported on this server.",
                    HttpStatus.SC_FORBIDDEN);
            // if we throw a status of 503, this means that while the token type was wrong, the
            // token still exists on the server.
        }
        // So we need to decide what the type of token is.
        OA2TokenForge tf = (OA2TokenForge) oa2SE.getTokenForge();
        ServiceTransaction t = null;
        switch (tf.getType(token)) {
            case OA2TokenForge.TYPE_ACCESS_TOKEN:
                t = oa2SE.getTransactionStore().get(tf.getAccessToken(token));
                break;
            case OA2TokenForge.TYPE_REFRESH_TOKEN:
                RefreshTokenStore refreshTokenStore = (RefreshTokenStore) oa2SE.getTransactionStore();
                t = refreshTokenStore.get(tf.getRefreshToken(token));
                break;
        }
        if (t != null) {
            if (!t.getClient().getIdentifier().equals(client.getIdentifier())) {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT, "Unauthorized client", HttpStatus.SC_UNAUTHORIZED);
            }
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("active", true);
            writeOK(resp, jsonObject);
            return;
        }
        JSONObject jwt;
        JSONObject jsonObject = new JSONObject();

        try {
            jwt = JWTUtil2.verifyAndReadJWT(token, oa2SE.getJsonWebKeys());
            // Since we only validate against our own keys (note we supply them rather than snooping the header for them)
            // if it passes here, this is valid for us.
            String id = jwt.getString(OA2Claims.JWT_ID);
            t = getTransFromToken(id);
            if (t == null) {
                jsonObject.put("active", false);
            } else {
                jsonObject.put("active", true);
            }
        } catch (Throwable throwable) {
            ServletDebugUtil.info(this, "Attempt to validate token \"" + token + "\" as a JWT failed:" + throwable.getMessage());
            // at this point we are out of options. This is not a JWT and it is not a basic token.
            // The correct response (as per spec( is an ok in that this token is not on valid.
            jsonObject.put("active", false);
        }

        writeOK(resp, jsonObject);
        return;


    }


}
