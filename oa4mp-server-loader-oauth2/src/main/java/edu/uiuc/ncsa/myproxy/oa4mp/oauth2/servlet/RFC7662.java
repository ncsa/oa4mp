package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import net.sf.json.JSONObject;

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
        State state;
        TokenImpl token;
        try {
            if (!HeaderUtils.getAuthHeader(req, HeaderUtils.BASIC_HEADER).isEmpty()) {
                state = checkBasic(req);
            } else {
                state = checkBearer(req);
            }
        }catch(OA2GeneralError x){
            DebugUtil.error(this, "Got exception checking bearer/basic header ",x);

            // This means that the token supplied does not exist (usually) or it is not really
            // a valid token. This servlet is not to throw exceptions except in very narrow cases
            // but to return false instead.
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("active", false);
            writeOK(resp, jsonObject);
            return;

        }

     if(state.txRecord != null ){
         JSONObject jsonObject = new JSONObject();
         jsonObject.put("active", state.txRecord.isValid());
         writeOK(resp, jsonObject);
         return;
     }

        if(state.transaction != null ){
            JSONObject jsonObject = new JSONObject();
            if(state.isAT){
                jsonObject.put("active", state.transaction.isAccessTokenValid());
            } else{
                jsonObject.put("active", state.transaction.isRefreshTokenValid());
            }
            writeOK(resp, jsonObject);
            return;
        }

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("active", false);
        writeOK(resp, jsonObject);
        return;


/*
        AccessTokenImpl at = UITokenUtils.getAT(getRawAT(req));
        OA2ServiceTransaction transaction;
        try {
            transaction = findTransaction(at);
        } catch (OA2GeneralError tt) {
            DebugUtil.warn(this, "token not found for " + at);
            // spec says that if the token is invalid return false. Do not throw exceptions!
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("active", false);
            writeOK(resp, jsonObject);
            return;
        }
        // OA2Client client = verifyClient(req, "Bearer");

        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);
        RefreshTokenImpl refreshToken = null;
        AccessTokenImpl accessToken = null;
        if (!tokenTypeHint.equals(TYPE_ACCESS_TOKEN) && !tokenTypeHint.equals(TYPE_REFRESH_TOKEN)) {
            // as per spec, throw the only exception this servlet is allowed
          throw  new OA2GeneralError("unsupported_token_type", // special error code defined in spec.
                    "The token type of \"" + tokenTypeHint + "\" is not supported on this server.",
                    HttpStatus.SC_FORBIDDEN,
                    null);
            // if we throw a status of 503, this means that while the token type was wrong, the
            // token still exists on the server.
        }
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, transaction.getOA2Client());
        ServiceTransaction t = null;


        switch (tokenTypeHint) {
            case TYPE_ACCESS_TOKEN:
                accessToken = OA2TokenUtils.getAT(token, oa2SE, keys);
                t = oa2SE.getTransactionStore().get(accessToken);
                break;
            case TYPE_REFRESH_TOKEN:
                refreshToken = OA2TokenUtils.getRT(token, oa2SE, keys);
                t = oa2SE.getTransactionStore().get(refreshToken);
                break;
        }
        if (t != null) {
            // Only exception this is allowed to throw
            if (!t.getClient().getIdentifier().equals(transaction.getOA2Client().getIdentifier())) {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "Unauthorized client",
                        HttpStatus.SC_UNAUTHORIZED,
                        null);
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

*/

    }


}
