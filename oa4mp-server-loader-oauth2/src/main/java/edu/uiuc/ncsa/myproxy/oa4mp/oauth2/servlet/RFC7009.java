package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Token Revocation endpoint. Points of policy for us is that revoking either an access token or
 * a refresh token invalidates both. We may revisit this policy but at the time of writing this, it
 * seems to be the most reasonable. This implements <a href="https://tools.ietf.org/html/rfc7009">RFC7009</a>.
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/20 at  12:24 PM
 */
// NOTE that there is a revocation servlet, but it does not handle JWts as access tokens and a few other
// things. This is to replace that.
public class RFC7009 extends TokenManagerServlet {

    @Override
    protected void doIt(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment().getTransactionStore();
        OA2Client client = verifyClient(req, "Basic");

        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);
        if (!tokenTypeHint.equals(TYPE_ACCESS_TOKEN) || !tokenTypeHint.equals(TYPE_REFRESH_TOKEN)) {
            // as per spec, throw the only exception this servlet is allowed
            new OA2GeneralError(
                    "unsupported_token_type", // special value in spec.
                    "The token type of \"" + tokenTypeHint + "\" is not supported on this server.",
                    HttpStatus.SC_FORBIDDEN,
                    null);
            // if we throw a status of 503, this means that while the token type was wrong, the
            // token still exists on the server.
        }
        if (checkToken(client, token)) {
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }

        // now we check that the token is a JWT.
        JSONObject jwt;
        try {
            jwt = JWTUtil2.verifyAndReadJWT(token, oa2SE.getJsonWebKeys());
            // Since we only validate against our own keys (note we supply them rather than snooping the header for them)
            // if it passes here, this is valid for us.
        } catch (Throwable throwable) {
            ServletDebugUtil.info(this, "Attempt to invalidate token \"" + token + "\" as a JWT failed:" + throwable.getMessage());
            // at this point we are out of options. This is not a JWT and it is not a basic token.
            // The correct response (as per spec( is an ok in that this token is not on valid.
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }
        // now we have to check that the JWT was issued by us.
        String id = jwt.getString(OA2Claims.JWT_ID);
        if (checkToken(client, id)) {
            resp.setStatus(HttpStatus.SC_OK);
            return;
        }
    }


    protected boolean checkToken(OA2Client requestingClient, String token) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment().getTransactionStore();

        ServiceTransaction t = getTransFromToken(token);
        if (t != null) {
            // Finally, don't let some other client try to revoke other people's tokens.
            if (!t.getClient().getIdentifier().equals(requestingClient.getIdentifier())) {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "Unauthorized client",
                        HttpStatus.SC_UNAUTHORIZED,
                        null);
            }
            oa2SE.getTransactionStore().remove(t.getIdentifier());
            return true;
        }
        return false;
    }


}
