package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.UITokenUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7523Constants;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenUtils;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7662Constants;
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
        String[] credentials = OA2HeaderUtils.getCredentialsFromHeaders(req, headerAuthz);
        // need to verify that this is an admin client.
        Identifier acID = BasicIdentifier.newID(credentials[OA2HeaderUtils.ID_INDEX]);
        if (!oa2SE.getClientStore().containsKey(acID)) {
            throw new GeneralException("Error: the given id of \"" + acID + "\" is not recognized as valid client.");
        }
        String adminSecret = credentials[OA2HeaderUtils.SECRET_INDEX];
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
     *
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
        return getState(req, state, oa2SE, client);
    }

    protected boolean isRFC7523Client(HttpServletRequest req) {
        System.out.println(getClass().getSimpleName() + ": " + req.getParameter(RFC7523Constants.CILENT_ASSERTION_TYPE));
        if (req.getParameter(RFC7523Constants.CILENT_ASSERTION_TYPE) != null &&
                req.getParameter(RFC7523Constants.CILENT_ASSERTION_TYPE).equals(RFC7523Constants.ASSERTION_JWT_BEARER)) {
            return true;
        }
        return false;
    }

    protected State check7523(HttpServletRequest req) throws Throwable {
        State state = new State();
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        OA2Client oa2Client = OA2HeaderUtils.getAndVerifyRFC7523Client(req, (OA2SE) getServiceEnvironment());
        return getState(req, state, oa2SE, oa2Client);
    }

    private State getState(HttpServletRequest req, State state, OA2SE oa2SE, OA2Client client) {
        OA2ServiceTransaction transaction;
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);

        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, client);
        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);
        transaction = getOA2ServiceTransactionBasic(state, oa2SE, keys, token, tokenTypeHint, debugger);
        state.transaction = transaction;
        // Final check. If the supplied transaction's client does not match the client credentials in the
        // headers. This prevents a malicious valid client from snooping other client's transactions.
        if (!client.getIdentifier().equals(transaction.getOA2Client().getIdentifier())) {
            debugger.info(this, "unauthorized client");
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "Unauthorized client",
                    HttpStatus.SC_UNAUTHORIZED,
                    null, client);// This compares the requsting client and the stored to see if they match
        }
        debugger.trace(this, "introspection endpoint basic auth ok.");
        return state;
    }

    private OA2ServiceTransaction getOA2ServiceTransactionBasic(State state, OA2SE oa2SE, JSONWebKeys keys, String token, String tokenTypeHint,
                                                                MetaDebugUtil debugger) {
        RefreshTokenImpl rt = null;
        AccessTokenImpl at = null;
        if (StringUtils.isTrivial(tokenTypeHint)) {
            // Fix CIL-1253
            try {
                rt = OA2TokenUtils.getRT(token, oa2SE, keys, debugger);

            } catch (Throwable t) {
                at = OA2TokenUtils.getAT(token, oa2SE, keys, debugger);
            }
        } else {
            switch (tokenTypeHint) {
                case TYPE_ACCESS_TOKEN:
                    at = OA2TokenUtils.getAT(token, oa2SE, keys, debugger);
                    break;
                case TYPE_REFRESH_TOKEN:
                    rt = OA2TokenUtils.getRT(token, oa2SE, keys, debugger);
                    break;
                default:
                    // as per spec, throw the only exception this servlet is allowed
                    throw new OA2GeneralError(
                            "unsupported_token_type", // special value in spec.
                            "The token type of \"" + tokenTypeHint + "\" is not supported on this server.",
                            HttpStatus.SC_FORBIDDEN,
                            null);
            }
        }
        OA2ServiceTransaction transaction = null;
        TXRecord txr = null;
        if (at == null && rt == null) {
            throw new NFWException("could not determine token type");
        }

        if (at != null) {
            state.accessToken = at;
            state.isAT = true;
            try {
                transaction = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(at);
            } catch (TransactionNotFoundException t) {
                txr = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(at.getJti()));
                transaction = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(txr.getParentID());
                state.txRecord = txr;
            }

        }
        if (rt != null) {
            state.refreshToken = rt;
            state.isAT = false;
            try {
                transaction = ((RefreshTokenStore) oa2SE.getTransactionStore()).get(rt);
            } catch (TransactionNotFoundException transactionNotFoundException) {
                // Just means this is probably in the TX store.
                txr = (TXRecord) oa2SE.getTxStore().get(BasicIdentifier.newID(rt.getJti()));
                transaction = (OA2ServiceTransaction) oa2SE.getTransactionStore().get(txr.getParentID());
                state.txRecord = txr;
            }
        }

        if (transaction == null) {
            //if (txr == null) {
            throw new OA2GeneralError(
                    OA2Errors.INVALID_TOKEN,
                    "invalid token",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
            //}
        }
        return transaction;
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
     *
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
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
        debugger.trace(this, "checked client, verifying access token is bearer token");
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, client);

        state.transaction = transaction;

        String token = req.getParameter(TOKEN);
        String tokenTypeHint = req.getParameter(TOKEN_TYPE_HINT);

        finishState(state, oa2SE, atBearer, keys, token, tokenTypeHint, debugger);
        debugger.trace(this, "access token is the bearer token");
        return state;
        // Finally, we have to check that the bearer and payload tokens match
        // This is, near as can be told, not in the spec., but makes perfectly good sense
        // that we don't want people revoking other's tokens.
    }

    private void finishState(State state, OA2SE oa2SE, AccessTokenImpl atBearer, JSONWebKeys keys, String token, String tokenTypeHint,
                             MetaDebugUtil debugger) {
        AccessTokenImpl accessToken = null;
        RefreshTokenImpl refreshToken = null;
        if (StringUtils.isTrivial(tokenTypeHint)) {
            // Fix CIL-1253.
            try {
                refreshToken = OA2TokenUtils.getRT(token, oa2SE, keys, debugger);
            } catch (Throwable t) {
                accessToken = OA2TokenUtils.getAT(token, oa2SE, keys, debugger);
            }
        } else {
            switch (tokenTypeHint) {
                case TYPE_ACCESS_TOKEN:
                    accessToken = OA2TokenUtils.getAT(token, oa2SE, keys, debugger);
                    break;
                case TYPE_REFRESH_TOKEN:
                    refreshToken = OA2TokenUtils.getRT(token, oa2SE, keys, debugger);
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
        }

            if (accessToken == null && refreshToken == null) {
                throw new NFWException("could not determine token type");
            }
            if (accessToken != null) {
                if (atBearer.getJti().equals(accessToken.getJti())) {
                    state.accessToken = atBearer;
                    state.isAT = true;
                } else {
                    throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "bearer and requested token must match",
                            HttpStatus.SC_UNAUTHORIZED, null);
                }
            }
            if (refreshToken != null) {
                state.refreshToken = refreshToken;
                state.isAT = false;
            }

    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        return null;
    }

    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws
            ServletException, IOException {
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
