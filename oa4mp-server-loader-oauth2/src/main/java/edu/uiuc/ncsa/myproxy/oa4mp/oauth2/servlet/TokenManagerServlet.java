package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.UITokenUtils;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2TokenForge;
import edu.uiuc.ncsa.security.oauth_2_0.server.RFC7662Constants;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.UITokenUtils.getRawAT;

/**
 * Superclass for {@link RFC7009} and{@link RFC7662} plus perhaps any others.
 * <p>Created by Jeff Gaynor<br>
 * on 2/17/20 at  2:21 PM
 */
public abstract class TokenManagerServlet extends BearerTokenServlet implements RFC7662Constants {

    /**
     * Used if the request has basic auth.
     *
     * @param req
     * @param headerAuthz
     * @return
     * @throws UnsupportedEncodingException
     */
    protected OA2Client verifyClient(HttpServletRequest req, String headerAuthz) throws UnsupportedEncodingException {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        String[] credentials = HeaderUtils.getCredentialsFromHeaders(req, headerAuthz);
        // need to verify that this is an admin client.
        Identifier acID = BasicIdentifier.newID(credentials[HeaderUtils.ID_INDEX]);
        if (!oa2SE.getClientStore().containsKey(acID)) {
            throw new GeneralException("Error: the given id of \"" + acID + "\" is not recognized as valid client.");
        }
        String adminSecret = credentials[HeaderUtils.SECRET_INDEX];
        if (adminSecret == null || adminSecret.isEmpty()) {
            throw new GeneralException("Error: missing secret.");
        }
        OA2Client client = (OA2Client) oa2SE.getClientStore().get(acID);
        if (!oa2SE.getClientApprovalStore().isApproved(acID)) {
            ServletDebugUtil.trace(this, "Client \"" + acID + "\" is not approved.");
            throw new GeneralException("error: This  client has not been approved.");
        }
        String hashedSecret = DigestUtils.sha1Hex(adminSecret);
        if (!client.getSecret().equals(hashedSecret)) {
            throw new GeneralException("error: client and secret do not match");
        }
        return client;
    }

    /**
     * This will process a request with basic authorization, peel off the supplied token and resolve it.
     * It will then find the transaction or token exchange (TX) record for the given token.
     * @param req
     * @return
     * @throws Throwable
     */
    protected State checkBasic(HttpServletRequest req) throws Throwable {
        State state = new State();
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        OA2Client client;
        OA2ServiceTransaction transaction;
        AccessTokenImpl at = null;
        RefreshTokenImpl rt = null;
        client = verifyClient(req, "Basic");// all that matters is it passes muster
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, client);
        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);
        switch (tokenTypeHint) {
            case TYPE_ACCESS_TOKEN:
                at = OA2TokenUtils.getAT(token, oa2SE, keys);
                state.accessToken = at;
                state.isAT = true;
                transaction = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(at);
                if(transaction == null){
                    TXRecord txr = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(at.getJti()));
                    transaction = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(txr.getParentID());
                    state.txRecord = txr;
                    state.transaction = transaction;
                }
                break;
            case TYPE_REFRESH_TOKEN:
                rt = OA2TokenUtils.getRT(token, oa2SE, keys);
                state.refreshToken = rt;
                state.isAT = false;
                transaction = ((RefreshTokenStore)oa2SE.getTransactionStore()).get(rt);
                if(transaction == null){
                    TXRecord txr = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(rt.getJti()));
                    transaction = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(txr.getParentID());
                    state.txRecord = txr;
                    state.transaction = transaction;

                }
                break;
            default:
                // as per spec, throw the only exception this servlet is allowed
                throw new OA2GeneralError(
                        "unsupported_token_type", // special value in spec.
                        "The token type of \"" + tokenTypeHint + "\" is not supported on this server.",
                        HttpStatus.SC_FORBIDDEN,
                        null);
                // if we throw a status of 503, this means that while the token type was wrong, the
                // token still exists on the server.

        }
        state.transaction = transaction;
        // Final check. If the supplied transaction's client does not match the client credentials in the
        // headers. This prevents a malicious valid client from snooping other client's transactions.
        if (!client.getIdentifier().equals(transaction.getOA2Client().getIdentifier())) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "Unauthorized client",
                    HttpStatus.SC_UNAUTHORIZED,
                    null);
        }

        return state;
    }

    public static class State {
        OA2ServiceTransaction transaction;
        boolean isAT = false;
        AccessTokenImpl accessToken;
        RefreshTokenImpl refreshToken;
        TXRecord txRecord;
    }

    /**
     * Checks the case that the request uses a bearer token. Same contract as{@link #checkBasic(HttpServletRequest)}
     * @param req
     * @return
     * @throws Throwable
     */
    protected State checkBearer(HttpServletRequest req) throws Throwable {
        State state = new State();

        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        OA2Client client;
        OA2ServiceTransaction transaction;
        AccessTokenImpl atBearer = null;
        AccessTokenImpl atPayload = null;
        RefreshTokenImpl rt = null;
        // try it as a bearer token
        atBearer = UITokenUtils.getAT(getRawAT(req));
        // So we have the access token used as a bearer token
        transaction = findTransaction(atBearer, state);
        client = transaction.getOA2Client();
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, client);

        state.transaction = transaction;

        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);
        switch (tokenTypeHint) {
            case TYPE_ACCESS_TOKEN:
                atPayload = OA2TokenUtils.getAT(token, oa2SE, keys);
                if (atBearer.equals(atPayload)) {
                    state.accessToken = atBearer;
                    state.isAT = true;
                } else {
                    throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "bearer and requested token must match",
                            HttpStatus.SC_UNAUTHORIZED, null);
                }
                break;
            case TYPE_REFRESH_TOKEN:
                state.refreshToken = OA2TokenUtils.getRT(token, oa2SE, keys);
                state.isAT = false;
                break;
            default:
                // as per spec, throw the only exception this servlet is allowed
                throw new OA2GeneralError(
                        "unsupported_token_type", // special value in spec.
                        "The token type of \"" + tokenTypeHint + "\" is not supported on this server.",
                        HttpStatus.SC_FORBIDDEN,
                        null);
                // if we throw a status of 503, this means that while the token type was wrong, the
                // token still exists on the server.

        }
        return state;
        // Finally, we have to check that the bearer and payload tokens match
        // This is, near as can be told, not in the spec., but makes perfectly good sense
        // that we don't want people revoking other's tokens.
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        httpServletResponse.setStatus(HttpStatus.SC_SERVICE_UNAVAILABLE);
        throw new ServletException("Unsupported operation");
    }

    protected int getTokenType(String token) {
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        return ((OA2TokenForge) oa2SE.getTokenForge()).getType(token);
    }

    protected void writeOK(HttpServletResponse httpServletResponse, JSONObject resp) throws IOException {
        if (resp != null) {
            httpServletResponse.setContentType("application/json");
            httpServletResponse.getWriter().println(resp.toString());
            httpServletResponse.getWriter().flush(); // commit it
        }
        httpServletResponse.setStatus(HttpStatus.SC_OK);
    }

    protected OA2ServiceTransaction getTransFromToken(String token) {
        if (TokenUtils.isBase32(token)) {
            token = TokenUtils.b32DecodeToken(token);
        }
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        OA2TokenForge tf = (OA2TokenForge) oa2SE.getTokenForge();
        switch (tf.getType(token)) {
            case OA2TokenForge.TYPE_AUTH_GRANT:
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "invalid request",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
    /*      This is the code to handle Authorization grant revocations if we ever want to do that too...
                case OA2TokenForge.TYPE_AUTH_GRANT:
                    t = oa2SE.getTransactionStore().get(tf.getAuthorizationGrant(token));
                    break;
    */
            case OA2TokenForge.TYPE_ACCESS_TOKEN:
                return (OA2ServiceTransaction) oa2SE.getTransactionStore().get(tf.getAccessToken(token));
            case OA2TokenForge.TYPE_REFRESH_TOKEN:
                RefreshTokenStore refreshTokenStore = (RefreshTokenStore) oa2SE.getTransactionStore();
                return refreshTokenStore.get(tf.getRefreshToken(token));
        }
        return null;
    }
}
