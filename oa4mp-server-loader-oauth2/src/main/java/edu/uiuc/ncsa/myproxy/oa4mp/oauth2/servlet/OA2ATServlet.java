package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ClaimSourceFactoryImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.SafeGCRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAccessTokenServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.qdl.exceptions.AssertionException;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTRunner;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptRuntimeException;
import edu.uiuc.ncsa.security.oauth_2_0.server.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceFactory;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.ClientUtils.computeATLifetime;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.ClientUtils.computeRefreshLifetime;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2TokenUtils.getTransactionFromTX;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628Constants2.DEVICE_CODE;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628Constants2.GRANT_TYPE_DEVICE_CODE;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8693Constants2.*;
import static edu.uiuc.ncsa.security.core.util.Identifiers.VERSION_1_0_TAG;
import static edu.uiuc.ncsa.security.core.util.Identifiers.VERSION_TAG;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;
import static edu.uiuc.ncsa.security.oauth_2_0.server.RFC8628Constants.DEFAULT_WAIT;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.JWT_ID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  2:03 PM
 */
public class OA2ATServlet extends AbstractAccessTokenServlet {
    // Don't really have a better place to put this.  TXRecord is not visible except in this module.
    public static Cleanup<Identifier, TXRecord> txRecordCleanup = null;

    public static LinkedList<ClaimSource> setupClaimSources(OA2ServiceTransaction transaction, OA2SE oa2SE) {
        LinkedList<ClaimSource> scopeHandlers = new LinkedList<>();
        DebugUtil.trace(OA2ATServlet.class, "setting up claim sources");
        if (oa2SE.getClaimSource() != null && oa2SE.getClaimSource().isEnabled()) {
            DebugUtil.trace(OA2ATServlet.class, "Adding default claim source.");

            scopeHandlers.add(oa2SE.getClaimSource());
        }
        ClaimSourceFactory oldSHF = ClaimSourceFactoryImpl.getFactory();
        ClaimSourceFactoryImpl.setFactory(new ClaimSourceFactoryImpl());

        OA2Client client = (OA2Client) transaction.getClient();
        DebugUtil.trace(OA2ATServlet.class, "Getting configured claim source factory " + ClaimSourceFactoryImpl.getFactory().getClass().getSimpleName());
        DebugUtil.trace(OA2ATServlet.class, "Adding other claim sources");

        scopeHandlers.addAll(ClaimSourceFactoryImpl.createClaimSources(oa2SE, transaction));
        DebugUtil.trace(OA2ATServlet.class, "Total claim source count = " + scopeHandlers.size());

        ClaimSourceFactoryImpl.setFactory(oldSHF);
        return scopeHandlers;
    }

    @Override
    public void destroy() {
        super.destroy();
        shutdownCleanup(txRecordCleanup); // try to shutdown cleanly
    }

    @Override
    public void preprocess(TransactionState state) throws Throwable {
        super.preprocess(state);
        state.getResponse().setHeader("Cache-Control", "no-store");
        state.getResponse().setHeader("Pragma", "no-cache");

        OA2ServiceTransaction st = (OA2ServiceTransaction) state.getTransaction();
        Map<String, String> p = state.getParameters();
        if (state.isRfc8628()) {
            String givenRedirect = p.get(OA2Constants.REDIRECT_URI);
            try {
                st.setCallback(URI.create(givenRedirect));
            } catch (Throwable t) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST_URI,
                        "invalid redirect URI \"" + givenRedirect + "\"",
                        st.getRequestState());
            }
            //Spec says that the redirect must match one of the ones stored and if not, the request is rejected.
            OA2ClientUtils.check(st.getClient(), givenRedirect);
            // Store the callback the user needs to use for this request, since the spec allows for many.

            // If there is a nonce in the initial request, it must be returned as part of the access token
            // response to prevent replay attacks.
            // Here is where we put the information from the session for generating claims in the id_token
            if (st.getNonce() != null && 0 < st.getNonce().length()) {
                p.put(OA2Constants.NONCE, st.getNonce());
            }
        }

        p.put(OA2Constants.CLIENT_ID, st.getClient().getIdentifierString());
    }


    protected String getClientSecret(HttpServletRequest request) {
        return ClientUtils.getClientSecret(request, getFirstParameterValue(request, CLIENT_SECRET));
    }


    /**
     * Contains the tests for executing a request based on its grant type. over-ride this as needed by writing your
     * code then calling super. Return <code>true</code> is the request is serviced and false otherwise.
     * This is invoked in the {@link #doIt(HttpServletRequest, HttpServletResponse)} method. If a grant is given'
     * that is not supported in this method, the servlet should reject the request, as per the OAuth 2 spec.
     *
     * @param request
     * @param response
     * @throws Throwable
     */
    protected boolean executeByGrant(String grantType,
                                     HttpServletRequest request,
                                     HttpServletResponse response) throws Throwable {
        DebugUtil.trace(this, "starting execute by grant, grant = \"" + grantType + "\"");
        DebugUtil.trace(this, "stored grant type is \"" + GRANT_TYPE_TOKEN_EXCHANGE + "\"");
        OA2Client client = (OA2Client) getClient(request);
        if (client == null) {
            warn("executeByGrant encountered a null client");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no such client");

        }
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        DebugUtil.trace(this, "8693 support enabled? " + oa2SE.isRfc8693Enabled());
        DebugUtil.trace(this, "grants equal? " + grantType.equals(GRANT_TYPE_TOKEN_EXCHANGE));
        if (!client.isPublicClient()) {
            verifyClientSecret(client, getClientSecret(request));
        }
        if (grantType.equals(GRANT_TYPE_TOKEN_EXCHANGE)) {
            if (!oa2SE.isRfc8693Enabled()) {
                warn("Client " + client.getIdentifierString() + " requested a token exchange but token exchange is not enabled onthis server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "token exchange not supported on this server ");
            }
            doRFC8693(client, request, response);
            DebugUtil.trace(this, "rfc8693 completed, returning... ");

            return true;
        }

        if (grantType.equals(GRANT_TYPE_DEVICE_CODE)) {
            if (!oa2SE.isRfc8628Enabled()) {
                warn("Client " + client.getIdentifierString() + " requested a token exchange but token exchange is not enabled onthis server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "device code flow not supported on this server ");
            }
            doRFC8628(client, request, response);
            DebugUtil.trace(this, "rfc8628 completed, returning... ");

            return true;
        }
        if (grantType.equals(OA2Constants.GRANT_TYPE_REFRESH_TOKEN)) {
            doRefresh(client, request, response);
            return true;
        }
        if (grantType.equals(OA2Constants.GRANT_TYPE_AUTHORIZATION_CODE)) {
            // OAuth 2. spec., section 4.1.3 states that the grant type must be included and it must be code.
            IssuerTransactionState state = doAT(request, response, client);
            writeATResponse(response, state);
            return true;
        }

        return false;
    }

    private void writeATResponse(HttpServletResponse response, IssuerTransactionState state) throws IOException {
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
        atResponse.setClaims(t.getUserMetaData());
        atResponse.write(response);
    }

    // Token exchange
    private void doRFC8693(OA2Client client,
                           HttpServletRequest request,
                           HttpServletResponse response) throws IOException {
        // https://tools.ietf.org/html/rfc8693

        //   printAllParameters(request);
        String subjectToken = getFirstParameterValue(request, SUBJECT_TOKEN);

        if (subjectToken == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject token");
        }
        String requestedTokenType = getFirstParameterValue(request, REQUESTED_TOKEN_TYPE);
        if (StringUtils.isTrivial(requestedTokenType)) {
            requestedTokenType = ACCESS_TOKEN_TYPE;
        }
        // And now do the spec stuff for the actor token
        String actorToken = getFirstParameterValue(request, ACTOR_TOKEN);
        String actorTokenType = getFirstParameterValue(request, ACTOR_TOKEN_TYPE);
        // We don't support the actor token, and the spec says that we can ignore it
        // *but* if it is missing and the actor token type is there, reject the request
        if ((actorToken == null && actorTokenType != null)) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    "actor token type is not allowed");
        }
        AccessTokenImpl accessToken = null;
        RefreshTokenImpl refreshToken = null;
        JSONObject sciTokens = null;
        OA2ServiceTransaction t = null;
        OA2SE oa2se = (OA2SE) getServiceEnvironment();
        OA2TokenForge tokenForge = ((OA2TokenForge) getServiceEnvironment().getTokenForge());
        String subjectTokenType = getFirstParameterValue(request, SUBJECT_TOKEN_TYPE);
        if (subjectTokenType == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject token type");
        }

        /*
        These can come as multiple space delimited string and as multiple parameters, so it is possible to get
        arrays of arrays of these and they have to be regularized to a single list for processing.
        NOTE: These are ignored for regular access tokens. For SciTokens we *should* allow exchanging
        a token for a weaker one. Need to figure out what weaker means though.
         */
        List<String> scopes = convertToList(request, OA2Constants.SCOPE);
        /*
          There is an entire RFC now associated with the resource parameter:

          https://tools.ietf.org/html/rfc8707

          Argh!
         */
        List<String> audience = convertToList(request, RFC8693Constants.AUDIENCE);
        List<String> resources = convertToList(request, RFC8693Constants.RESOURCE);

        TXRecord oldTXR = null;

        //CIL-974
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2se, client);
        switch (subjectTokenType) {
            case ACCESS_TOKEN_TYPE:
                accessToken = OA2TokenUtils.getAT(subjectToken, oa2se, keys);
                t = (OA2ServiceTransaction) getTransactionStore().get(accessToken);
                break;
            case REFRESH_TOKEN_TYPE:
                refreshToken = OA2TokenUtils.getRT(subjectToken, oa2se, keys);
                RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
                t = rts.get(refreshToken);
                break;
        }

        if (t == null) {
            // if there is no such transaction found, then this is probably from a previous exchange. Go find it
            t = getTransactionFromTX(accessToken, t, oa2se);
        }
        if (t == null) {
            // Still null. Ain't one no place. Bail.
            throw new OA2ATException(OA2Errors.INVALID_GRANT, "no pending transaction found.");
        }
        // Don't let an authorized client access anything unless it is the client
        // of record in the transaction -- that way a valid client can't send someone else's
        // token and get information.
        if (!t.getClient().getIdentifierString().equals(client.getIdentifierString())) {
            // NOTE don't throw an OA2 AT Exception here since that returns some state about
            // the original client. Wrong client means it bombs.
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "wrong client, access denied",
                    HttpStatus.SC_UNAUTHORIZED, null);
        }
        // Finally can check access here. Access for exchange is same as for refresh token.
        if (!t.getFlowStates().acceptRequests || !t.getFlowStates().refreshToken) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "token exchange access denied",
                    t.getRequestState());
        }
        /*
           Earth shaking change is that we need to create a new token exchange record for each exchange since the tokens
           have a lifetime and lifecycle of their own. Once in the wild, people may come back to this
           service and swap them willy nilly.
         */

        TXRecord newTXR = (TXRecord) oa2se.getTxStore().create();
        newTXR.setTokenType(requestedTokenType);
        newTXR.setParentID(t.getIdentifier());
        if (!audience.isEmpty()) {
            newTXR.setAudience(audience);
        }
        if (!scopes.isEmpty()) {
            ServletDebugUtil.trace(this, "user requested scopes:" + scopes);
            newTXR.setScopes(scopes);
        } else {
            // If no scopes sent with request, revert to scopes in original request.
            ServletDebugUtil.trace(this, "NO user requested scopes");
            //   newTXR.setScopes(t.getScopes());
        }

        if (!resources.isEmpty()) {
            // convert to URIs
            ArrayList<URI> r = new ArrayList<>();
            for (String x : resources) {
                try {
                    r.add(URI.create(x));
                } catch (Throwable throwable) {
                    info("rejected resource request \"" + x + "\"");
                }
            }
            newTXR.setResource(r);
        }

        RTIRequest rtiRequest = new RTIRequest(request, t, t.getAccessToken(), oa2se.isOIDCEnabled());
        RTI2 rtIssuer = new RTI2(getTF2(), getServiceEnvironment().getServiceAddress());
        RTIResponse rtiResponse = (RTIResponse) rtIssuer.process(rtiRequest);
        ServletDebugUtil.trace(this, "rti response=" + rtiResponse);
        rtiResponse.setSignToken(client.isSignTokens());
        // These are the claims that are returned in the RFC's required response. They have nothing to do
        // with id token claims, fyi.
        JSONObject rfcClaims = new JSONObject();
        newTXR.setIssuedAt(System.currentTimeMillis());

        switch (requestedTokenType) {
            default:
            case ACCESS_TOKEN_TYPE:
                // do NOT reset the refresh token
                // All the machinery from here out gets the RT from the rtiResponse.
                rfcClaims.put(ISSUED_TOKEN_TYPE, ACCESS_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_BEARER); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                rfcClaims.put(OA2Constants.EXPIRES_IN, t.getAccessTokenLifetime() / 1000); // internal in ms., external in sec.
                newTXR.setLifetime(t.getAccessTokenLifetime());

                rtiResponse.setRefreshToken(null); // no refresh token should get processed
                newTXR.setIdentifier(BasicIdentifier.newID(rtiResponse.getAccessToken().getToken()));
                //t.setAccessToken(rtiResponse.getAccessToken()); // update to new AT
                break;
            case REFRESH_TOKEN_TYPE:
                rfcClaims.put(ISSUED_TOKEN_TYPE, REFRESH_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_N_A); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                rfcClaims.put(OA2Constants.EXPIRES_IN, t.getRefreshTokenLifetime() / 1000); // internal in ms., external in sec.
                newTXR.setLifetime(t.getRefreshTokenLifetime());
                newTXR.setIdentifier(BasicIdentifier.newID(rtiResponse.getRefreshToken().getToken()));
                //t.setRefreshToken(rtiResponse.getRefreshToken()); // Update to new RT
                break;
        }
        newTXR.setExpiresAt(newTXR.getIssuedAt() + newTXR.getLifetime());
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2se, t, newTXR, t.getOA2Client().getConfig()));
        try {
            OA2ClientUtils.setupHandlers(jwtRunner, oa2se, t, newTXR, request);
            // NOTE WELL that the next two lines are where our identifiers are used to create JWTs (like SciTokens)
            // so if this is not done, the wrong token type will be returned.
            jwtRunner.doTokenExchange();

        } catch (AssertionException assertionError) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    assertionError.getMessage(),
                    HttpStatus.SC_BAD_REQUEST, t.getRequestState());
        } catch (ScriptRuntimeException sre) {
            // Client threw an exception.
            throw new OA2ATException(sre.getRequestedType(), sre.getMessage(),
                    sre.getStatus(), t.getRequestState());
        } catch (IllegalAccessException iax) {
            // implies that the at some point there was a change in access allowed, e.g. a script
            // set a policy that denied it.
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    t.getRequestState());

        } catch (Throwable throwable) {
            /*
            NOTE: If there is some other error (such as a bad QDL script) and this fails, then as a fallback position
            this will return the token with the same claims as are currently available in the handler.
            There is no good way to communicate this to the user though.
             */
            ServletDebugUtil.warn(this, "*** Unable to update claims on token exchange: \"" + throwable.getMessage() + "\"");
        }
        setupTokens(client, rtiResponse, oa2se, t, jwtRunner);

        if (rtiResponse.hasRefreshToken()) {
            // Maddening part of the spec is that the access token claim can be a refresh token.
            // User has to look at the returned token type.
            if (rtiResponse.getRefreshToken().isJWT()) {
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().getToken()); // Required
                rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().getToken()); // Optional
            } else {
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Required
                rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Optional
            }
        } else {
            if (((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().getToken()); // Required.
            } else {
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().encodeToken()); // Required.
            }
            // create scope string  Remember that these may have been changed by a script,
            // so here is the right place to set it.
            rfcClaims.put(OA2Constants.SCOPE, listToString(newTXR.getScopes()));

        }
        ServletDebugUtil.trace(this, "rfc claims returned:" + rfcClaims.toString(1));
        /*

         Important note: In the RFC 8693 spec., access_token MUST be returned, however, it explains that this
         is so named merely for compatibility with OAuth 2.0 request/response constructs. The actual
         content of this is undefined.

         Our policy: access_token contains whatever the requested token is. Look at the returned_token_type
         to see what they got. As a convenience, if there is a refresh token, that will be returned as the
         refresh_token claim.
         */

        // The other components (access, refresh token) have responses that handle setting the encoding and
        // char type. We have to set it manually here.
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");

        newTXR.setValid(true); // automatically.
        oa2se.getTxStore().save(newTXR);
        getTransactionStore().save(t);
        PrintWriter osw = response.getWriter();
        rfcClaims.write(osw);
        osw.flush();
        osw.close();


    }


    /**
     * Convert a string or list of strings to a list of them. This is for lists of space delimited values
     * The spec allows for multiple value which in practice can also mean that a client makes the request with
     * multiple parameters, so we have to snoop for those and for space delimited strings inside of those.
     * This is used by RFC 8693 and specific to it.
     *
     * @param req
     * @param parameterName
     * @return
     */
    protected List<String> convertToList(HttpServletRequest req, String parameterName) {
        ArrayList<String> out = new ArrayList<>();
        String[] rawValues = req.getParameterValues(parameterName);
        if (rawValues == null) {
            return out;
        }
        for (String v : rawValues) {
            StringTokenizer st = new StringTokenizer(v);
            while (st.hasMoreTokens()) {
                out.add(st.nextToken());
            }
        }
        return out;
    }

    protected List<URI> convertToURIList(HttpServletRequest req, String parameterName) {
        ArrayList<URI> out = new ArrayList<>();
        String[] rawValues = req.getParameterValues(parameterName);
        if (rawValues == null) {
            return out;
        }
        for (String v : rawValues) {
            StringTokenizer st = new StringTokenizer(v);
            while (st.hasMoreTokens()) {
                try {
                    out.add(URI.create(st.nextToken()));
                } catch (Throwable t) {
                    // just skip it
                }
            }
        }
        return out;
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        String grantType = getFirstParameterValue(request, OA2Constants.GRANT_TYPE);

        if (isEmpty(grantType)) {
            warn("Error servicing request. No grant type was given. Rejecting request.");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing grant type");
        }
        if (executeByGrant(grantType, request, response)) {
            return;
        }
        warn("Error: grant type +\"" + grantType + "\" was not recognized. Request rejected.");
        throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                "unsupported grant type \"" + grantType + "\"");
    }

    @Override
    protected ATRequest getATRequest(HttpServletRequest request, ServiceTransaction transaction) {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;
        // Set these in the transaction then send it along.
        t.setAccessTokenLifetime(computeATLifetime(t, (OA2SE) getServiceEnvironment()));
        if (((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled()) {
            t.setRefreshTokenLifetime(computeRefreshLifetime(t, (OA2SE) getServiceEnvironment()));
        }

        return new ATRequest(request, transaction);
    }

    @Override
    protected AuthorizationGrantImpl checkAGExpiration(AuthorizationGrant ag) {
        if (!ag.getToken().contains(VERSION_TAG)) {
            // update old version 1 token.
            AuthorizationGrantImpl ag0 = (AuthorizationGrantImpl) ag;
            ag0.setIssuedAt(DateUtils.getDate(ag0.getToken()).getTime());
            ag0.setLifetime(OA2ConfigurationLoader.AUTHORIZATION_GRANT_LIFETIME_DEFAULT);
            ag0.setVersion(VERSION_1_0_TAG);  // just in case.
            return ag0;
        }
        if (ag.isExpired()) {
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "grant expired");
        }
        return null;
    }

    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = doDelegation(client, request, response);
        return doAT(state, client);
    }

    protected IssuerTransactionState doAT(IssuerTransactionState state, OA2Client client) throws Throwable {
        // Grants are checked in the doIt method
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();

        atResponse.setSignToken(client.isSignTokens());
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        OA2ServiceTransaction st2 = (OA2ServiceTransaction) state.getTransaction();
        if (!st2.getFlowStates().acceptRequests || !st2.getFlowStates().accessToken || !st2.getFlowStates().idToken) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    st2.getRequestState());
        }

        if (!st2.getClient().getIdentifierString().equals(client.getIdentifierString())) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "wrong client, access denied",
                    HttpStatus.SC_UNAUTHORIZED, null);
        }
        st2.setAccessToken(atResponse.getAccessToken()); // needed if there are handlers later.
        st2.setRefreshToken(atResponse.getRefreshToken()); // ditto. Might be null.
        JWTRunner jwtRunner = new JWTRunner(st2, ScriptRuntimeEngineFactory.createRTE(oa2SE, st2, st2.getOA2Client().getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, st2, state.getRequest());
        if (state.isRfc8628() || st2.getAuthorizationGrant().getVersion() == null || st2.getAuthorizationGrant().getVersion().equals(VERSION_1_0_TAG)) {
            // Handlers have not been initialized yet. Either because of old tokens or rfc 8628 (so no tokens).
            jwtRunner.initializeHandlers();
        }
        try {
            jwtRunner.doTokenClaims();
        } catch (AssertionException assertionError) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, assertionError.getMessage(),HttpStatus.SC_BAD_REQUEST, st2.getRequestState());
        } catch (ScriptRuntimeException sre) {
            // Client threw an exception.
            throw new OA2ATException(sre.getRequestedType(), sre.getMessage(), sre.getStatus(), st2.getRequestState());
        } catch (IllegalAccessException iax) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    st2.getRequestState());
        }

        if (!client.isRTLifetimeEnabled()) {
            atResponse.setRefreshToken(null);
        }
        setupTokens(client, atResponse, oa2SE, st2, jwtRunner);

        getTransactionStore().save(st2);
        // Check again after doing token claims in case a script changed it.
        if (!st2.getFlowStates().acceptRequests || !st2.getFlowStates().accessToken || !st2.getFlowStates().idToken) {
            throw new OA2ATException(
                    OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    st2.getRequestState());
        }
        return state;
    }

    /**
     * This will take the {@link IDTokenResponse} and if necessary create a signed JWT, setting the jti to the
     * returned token. It will then set the new JWT in the tokenResponse to be returned to the user.
     * <br/>
     * <b>Contract:</b> the idTokenResponse must have an access token and should only have a refresh token if
     * that is allowed. If the refresh token is null, nothing will be done with the refresh token.
     *
     * @param client
     * @param tokenResponse
     * @param oa2SE
     * @param st2
     * @param jwtRunner
     */
    private void setupTokens(OA2Client client,
                             IDTokenResponse tokenResponse,
                             OA2SE oa2SE,
                             OA2ServiceTransaction st2,
                             JWTRunner jwtRunner) {
        setupTokens(client, tokenResponse, oa2SE, st2, jwtRunner, false);
    }

    private void setupTokens(OA2Client client,
                             IDTokenResponse tokenResponse,
                             OA2SE oa2SE,
                             OA2ServiceTransaction st2,
                             JWTRunner jwtRunner,
                             boolean isTokenExchange) {
        VirtualOrganization vo = oa2SE.getVO(client.getIdentifier());
        JSONWebKey key = null;
        if (vo != null && vo.getJsonWebKeys() != null) {
            key = vo.getJsonWebKeys().get(vo.getDefaultKeyID());
        } else {
            key = oa2SE.getJsonWebKeys().getDefault();
        }
        if (jwtRunner.hasATHandler()) {
            AccessToken newAT = jwtRunner.getAccessTokenHandler().getSignedAT(key);
            tokenResponse.setAccessToken(newAT);
            DebugUtil.trace(this, "Returned AT from handler:" + newAT + ", for claims " + st2.getATData().toString(2));
        }
        tokenResponse.setClaims(st2.getUserMetaData());
        DebugUtil.trace(this, "set token signing flag =" + tokenResponse.isSignToken());
        // no processing of the refresh token is needed if there is none.
        if (!tokenResponse.hasRefreshToken()) {
            return;
        }
        if (!client.isRTLifetimeEnabled() && oa2SE.isRefreshTokenEnabled()) {
            // Since this bit of information could be extremely useful if a service decides
            // to start issuing refresh tokens after
            // clients have been registered, it should be logged.
            info("Refresh tokens are disabled for client " + client.getIdentifierString() + ", but enabled on the server. No refresh token will be made.");
        }
        if (client.isRTLifetimeEnabled() && oa2SE.isRefreshTokenEnabled()) {
            RefreshTokenImpl rt = tokenResponse.getRefreshToken();
            // rt is used as a key in the database. If the refresh token is  JWT, it will be used as the jti.
            st2.setRefreshToken(rt);
            st2.setRefreshTokenValid(true);
            if (jwtRunner.hasRTHandler()) {
                RefreshTokenImpl newRT = (RefreshTokenImpl) jwtRunner.getRefreshTokenHandler().getSignedRT(null); // unsigned, for now
                tokenResponse.setRefreshToken(newRT);
                DebugUtil.trace(this, "Returned RT from handler:" + newRT + ", for claims " + st2.getRTData().toString(2));
            }
        } else {
            // Even if a token is sent, do not return a refresh token.
            // This might be in a legacy case where a server changes it policy to prohibit  issuing refresh tokens but
            // an outstanding transaction has one.   
            tokenResponse.setRefreshToken(null);
        }
    }


    /**
     * This finds the client identifier either as a parameter or in the authorization header and uses
     * that to get the client. It will also check if the client has been approved and throw an
     * exception if that is not the case. You must separately check the secret as needed.
     *
     * @param request
     * @return
     */
    @Override
    public Client getClient(HttpServletRequest request) {
        // Check is this is in the headers. If not, fall through to checking parameters.
        OA2Client client = null;
        Identifier paramID = HeaderUtils.getIDFromParameters(request);
        Identifier headerID = null;
        try {
            headerID = HeaderUtils.getIDFromHeaders(request);
        } catch (UnsupportedEncodingException e) {
            throw new NFWException("Error: internal use of UTF-8 encoding failed");
        } catch (Throwable tt) {
            ServletDebugUtil.trace(this.getClass(), "Got an exception checking for the header. " +
                    "This is usually benign:\"" + tt.getMessage() + "\"");
        }
        // we have to check that if we get both of these they refer to the same client, so someone
        // cannot hijack the session
        if (paramID == null) {
            if (headerID == null) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no client identifier given");
            }
            client = (OA2Client) getClient(headerID);
        } else {
            if (headerID == null) {
                client = (OA2Client) getClient(paramID);
            } else {
                if (!paramID.equals(headerID)) {
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST, "too many client identifiers");
                }
                client = (OA2Client) getClient(paramID); // doesn't matter which id we use since they are equal.
            }
        }

        checkClientApproval(client);


        return client;
    }

    public void verifyClientSecret(OA2Client client, String rawSecret) {
        ClientUtils.verifyClientSecret(client, rawSecret, true);
        // Fix for CIL-332
/*
        if (rawSecret == null) {
            DebugUtil.trace(this, "doIt: no secret, throwing exception.");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "missing secret");
        }
        if (StringUtils.isTrivial(client.getSecret())) {
            // Since clients can be administered by others now, we are finding that they sometimes
            // may change their scopes. If a client is public, there is no secret, but if
            // a client later is updated to have different scopes, then trying to use it for other
            // purposes gets an NPE here. Tell them when they use their client next rather
            // than blowing up with an NPE.
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "client has no configured secret",null);
        }

        // TODO -- replace next call with sha1Hex(rawSecret)? Need to know side effects first!

        if (!client.getSecret().equals(DigestUtils.shaHex(rawSecret))) {
            DebugUtil.trace(this, "doIt: bad secret, throwing exception.");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "incorrect secret");
        }
*/

    }

    protected OA2ServiceTransaction getByRT(RefreshToken refreshToken) throws IOException {
        if (refreshToken == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing refresh token");
        }
        RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
        try {
            JSONObject jsonObject = JWTUtil2.verifyAndReadJWT(refreshToken.getToken(), ((OA2SE) getServiceEnvironment()).getJsonWebKeys());
            if (jsonObject.containsKey(JWT_ID)) {
                refreshToken = new RefreshTokenImpl(URI.create(jsonObject.getString(JWT_ID)));
            } else {
                throw new OA2ATException(OA2Errors.INVALID_GRANT, "refresh token is a JWT, but has no " + JWT_ID + " claim.");
            }
        } catch (Throwable t) {

        }
        if (refreshToken.isExpired()) {
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "token expired");
        }
        // Can only determine if token is valid after we get the transaction and examine it.
        return rts.get(refreshToken);
    }

    protected OA2TokenForge getTF2() {
        return (OA2TokenForge) getServiceEnvironment().getTokenForge();
    }

    protected TransactionState doRefresh(OA2Client c, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Grants are checked in the doIt method

        String rawRefreshToken = request.getParameter(OA2Constants.REFRESH_TOKEN);
        if (c == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "Could not find the client associated with refresh token \"" + rawRefreshToken + "\"");
        }
        // Check if its a token or JWT
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        //CIL-974:
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, c);

        boolean tokenVersion1 = false;
        RefreshTokenImpl oldRT = OA2TokenUtils.getRT(rawRefreshToken, oa2SE, keys);

        OA2ServiceTransaction t = null;
        if (oldRT.isExpired()) {
            DebugUtil.trace(this, "expired refresh token \"" + oldRT.getToken() + "\" for client " + c.getIdentifierString());
            throw new OA2ATException(OA2Errors.INVALID_GRANT, "expired refresh token", HttpStatus.SC_BAD_REQUEST, null);
        }
        try {
            // Fix for CIL-882
            t = getByRT(oldRT);
            if (!t.getClient().getIdentifier().equals(c.getIdentifier())) {
                ServletDebugUtil.trace(this, "transaction lists client id \"" + t.getClient().getIdentifierString()
                        + "\", but the client in the request is \"" + c.getIdentifierString() + "\". Request rejected.");
                throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                        "wrong client",
                        HttpStatus.SC_BAD_REQUEST, null);

            }
        } catch (TransactionNotFoundException e) {
            String message = "The refresh token \"" + oldRT.getToken() + "\" for client " + c.getIdentifierString() + " is not expired, but also was not found.";
            ServletDebugUtil.trace(this, message);
            info(message);
            throw new OA2ATException(OA2Errors.INVALID_TOKEN, "The token \"" + oldRT.getToken() + "\" could not be associated with a pending flow",
                    HttpStatus.SC_BAD_REQUEST, null);
        }
        if (tokenVersion1) {
            // Can't fix it until we have the right transaction.
            t.setRefreshTokenLifetime(computeRefreshLifetime(t, oa2SE));
            t.setAccessTokenLifetime(computeATLifetime(t, oa2SE));
        }

        AccessTokenImpl at = (AccessTokenImpl) t.getAccessToken();

        List<String> scopes = convertToList(request, OA2Constants.SCOPE);
        List<String> audience = convertToList(request, RFC8693Constants.AUDIENCE);
        List<URI> resources = convertToURIList(request, RFC8693Constants.RESOURCE);
        TXRecord txRecord = null;
        if (!scopes.isEmpty() || !audience.isEmpty() || !resources.isEmpty()) {
            txRecord = new TXRecord(t.getIdentifier());
            txRecord.setScopes(scopes);
            txRecord.setAudience(audience);
            txRecord.setResource(resources);
        }

        if (t == null || !t.isRefreshTokenValid()) {
            DebugUtil.trace(this, "Missing refresh token.");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    "The refresh token is no longer valid.",
                    t.getRequestState());
        }
        DebugUtil.trace(this, "flow states = " + t.getFlowStates());
        if (!t.getFlowStates().acceptRequests || !t.getFlowStates().refreshToken) {
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "Refresh token access denied.",
                    t.getRequestState());
        }
        if ((!(oa2SE).isRefreshTokenEnabled()) || (!c.isRTLifetimeEnabled())) {
            throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                    "Refresh tokens are not supported on this server.",
                    t.getRequestState());
        }
        t.setRefreshTokenValid(false); // this way if it fails at some point we know it is invalid.
        RTIRequest rtiRequest = new RTIRequest(request, t, at, oa2SE.isOIDCEnabled());
        RTI2 rtIssuer = new RTI2(getTF2(), getServiceEnvironment().getServiceAddress());

        RTIResponse rtiResponse = (RTIResponse) rtIssuer.process(rtiRequest);
        rtiResponse.setSignToken(c.isSignTokens());
        if (c.isRTLifetimeEnabled() && oa2SE.isRefreshTokenEnabled()) {
            t.setRefreshToken(rtiResponse.getRefreshToken());
        } else {
            rtiResponse.setRefreshToken(null);
        }
        // Note for CIL-525: Here is where we need to recompute the claims. If a request comes in for a new
        // refresh token, it has to be checked against the recomputed claims. Use case is that a very long-lived
        // refresh token is issued, a user is no longer associated with a group and her access is revoked, then
        // attempts to get another refresh token (e.g. by some automated service everyone forgot was running) should fail.
        // Which claims to recompute? All of them? It is possible that there are several sources that need to be taken in to
        // account that may not be available, e.g. if there are shibboleth headers as in initial source...
        // Executive decision is to re-run the sources from after the bootstrap. The assumption with bootstrap sources
        // is that they exist only for the initialization.

        t.setAccessToken(rtiResponse.getAccessToken());
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, txRecord, t.getOA2Client().getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, t, txRecord, request);
        try {
            jwtRunner.doRefreshClaims();
        } catch (AssertionException assertionError) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, assertionError.getMessage(),HttpStatus.SC_BAD_REQUEST, t.getRequestState());
        } catch (ScriptRuntimeException sre) {
            // Client threw an exception.
            throw new OA2ATException(sre.getRequestedType(), sre.getMessage(), sre.getStatus(), t.getRequestState());
        } catch (IllegalAccessException iax) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    t.getRequestState());
        } catch (Throwable throwable) {
            ServletDebugUtil.trace(this, "Unable to update claims on token refresh", throwable);
            ServletDebugUtil.warn(this, "Unable to update claims on token refresh: \"" + throwable.getMessage() + "\"");
        }
        setupTokens(c, rtiResponse, oa2SE, t, jwtRunner);
        // At this point, key in the transaction store is the grant, so changing the access token
        // over-writes the current value. This practically invalidates the previous access token.
        getTransactionStore().remove(t.getIdentifier()); // this is necessary to clear any caches.
        ArrayList<String> targetScopes = new ArrayList<>();

        boolean returnScopes = false; // set true if something is requested we don't support
        for (String s : t.getScopes()) {
            if (oa2SE.getScopes().contains(s)) {
                targetScopes.add(s);
            } else {
                returnScopes = true;
            }
        }
        if (returnScopes) {
            rtiResponse.setSupportedScopes(targetScopes);
        }

        rtiResponse.setServiceTransaction(t);
        VirtualOrganization vo = oa2SE.getVO(c.getIdentifier());

        if (vo == null) {
            rtiResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        } else {
            rtiResponse.setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        rtiResponse.setClaims(t.getUserMetaData());
        getTransactionStore().save(t);
        rtiResponse.write(response);
        IssuerTransactionState state = new IssuerTransactionState(
                request,
                response,
                rtiResponse.getParameters(),
                t,
                rtiResponse);
        DebugUtil.trace(this, "done with token refresh, returning.");
        return state;
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {

        ATIResponse2 atResponse = (ATIResponse2) iResponse;

        TransactionStore transactionStore = getTransactionStore();
        BasicIdentifier basicIdentifier = new BasicIdentifier(atResponse.getParameters().get(OA2Constants.AUTHORIZATION_CODE));
        DebugUtil.trace(this, "getting transaction for identifier=" + basicIdentifier);
        OA2ServiceTransaction transaction = null;
        // Transaction may have unsaved state in it. Don't just get rid of it if it is passed in.
        if (((ATIResponse2) iResponse).getServiceTransaction() == null) {
            transaction = (OA2ServiceTransaction) transactionStore.get(basicIdentifier);
        } else {
            transaction = (OA2ServiceTransaction) ((ATIResponse2) iResponse).getServiceTransaction();
        }
        if (transaction == null) {
            // Then this request does not correspond to an previous one and must be rejected asap.
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    "No pending transaction found for id=" + basicIdentifier);
        }
        if (!transaction.isAuthGrantValid()) {
            String msg = "Error: Attempt to use invalid authorization code \"" + basicIdentifier + "\".  Request rejected.";
            warn(msg);
            throw new OA2ATException(
                    OA2Errors.INVALID_REQUEST,
                    msg,
                    transaction.getRequestState());
        }

        boolean uriOmittedOK = false;
        if (!atResponse.getParameters().containsKey(OA2Constants.REDIRECT_URI)) {
            // OK, the spec states that if we get to this point (so the redirect URI has been verified) a client with a
            // **single** registered redirect uri **MAY** be omitted. It seems that various python libraries do not
            // send it in this case, so we have the option to accept or reject the request.
            if (((OA2Client) transaction.getClient()).getCallbackURIs().size() == 1) {
                uriOmittedOK = true;
            } else {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST_URI, "No redirect URI. Request rejected.");
            }
        }
        if (!uriOmittedOK) {
            // so if the URI is sent, verify it
            URI uri = URI.create(atResponse.getParameters().get(OA2Constants.REDIRECT_URI));
            if (!transaction.getCallback().equals(uri)) {
                String msg = "Attempt to use alternate redirect uri rejected.";
                warn(msg);
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, msg);
            }
        }
        /*
         CIL-586 fix: Now we have to determine which scopes to return
           The spec says we don't have to return anything if the requested scopes are the same as the
           supported scopes. Otherwise, return what scopes *are* supported.
         */
        ArrayList<String> targetScopes = new ArrayList<>();
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

        boolean returnScopes = false; // set true if something is requested we don't support
        for (String s : transaction.getScopes()) {
            if (oa2SE.getScopes().contains(s)) {
                targetScopes.add(s);
            } else {
                returnScopes = true;
            }
        }
        if (returnScopes) {
            atResponse.setSupportedScopes(targetScopes);
        }

        //      atResponse.setClaimSources(setupClaimSources(transaction, oa2SE));

        atResponse.setServiceTransaction(transaction);
        VirtualOrganization vo = oa2SE.getVO(transaction.getClient().getIdentifier());
        if (vo == null) {
            atResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        } else {
            atResponse.setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        atResponse.setClaims(transaction.getUserMetaData());
        // Need to do some checking but for now, just return transaction
        //return null;
        return transaction;
    }

    @Override
    protected ServiceTransaction getTransaction(AuthorizationGrant ag, HttpServletRequest req) throws ServletException {

        OA2ServiceTransaction transaction = (OA2ServiceTransaction) getServiceEnvironment().getTransactionStore().get(ag);
        if (transaction == null) {
            if (ag instanceof AuthorizationGrantImpl) {
                AuthorizationGrantImpl agi = (AuthorizationGrantImpl) ag;
                if (agi.isExpired()) {
                    ServletDebugUtil.trace(this, "Token \"" + ag.getToken() + "\" has expired");
                    throw new OA2ATException(OA2Errors.INVALID_GRANT,
                            "expired token");
                }
            }
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "invalid token");

        }
        if (!transaction.isAuthGrantValid()) {
            ServletDebugUtil.trace(this, "Token \"" + ag.getToken() + "\" is invalid");
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "invalid token",
                    transaction.getRequestState());
        }
        return transaction;
    }

    protected String listToString(List scopes) {
        String requestedScopes = "";
        if (scopes == null || scopes.isEmpty()) {
            return requestedScopes;
        }
        boolean firstPass = true;
        for (Object x : scopes) {
            if (x == null) {
                continue;
            }
            if (firstPass) {
                firstPass = false;
                requestedScopes = x.toString();
            } else {
                requestedScopes = requestedScopes + " " + x.toString();
            }
        }
        return requestedScopes;
    }

    /**
     * device flow
     *
     * @param client
     * @param request
     * @param response
     * @throws Throwable
     */
    protected void doRFC8628(OA2Client client, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        printAllParameters(request);
        long now = System.currentTimeMillis();
        String rawSecret = getClientSecret(request);

        verifyClientSecret(client, rawSecret);
        String deviceCode = request.getParameter(DEVICE_CODE);
        if (StringUtils.isTrivial(deviceCode)) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                    "Missing " + DEVICE_CODE + " parameter",
                    HttpStatus.SC_UNAUTHORIZED,
                    null);
        }
        URI ag;
        try {
            ag = URI.create(deviceCode);
        } catch (Throwable t) {
            info("Failed to create " + DEVICE_CODE + " from input \"" + deviceCode + "\"");
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                    DEVICE_CODE + " is not a uri", HttpStatus.SC_UNAUTHORIZED, null);
        }
        AuthorizationGrantImpl authorizationGrant = new AuthorizationGrantImpl(ag);
        try {
            checkAGExpiration(authorizationGrant);
        } catch (OA2ATException atException) {
            // even though the token endpoint has a perfectly good way of communicating
            // that the token is expired, the RFC requires this instead
            throw new OA2ATException("expired_token", DEVICE_CODE + " expired");
        }
        OA2ServiceTransaction transaction = (OA2ServiceTransaction) getTransaction(authorizationGrant);
        if (!transaction.isAuthGrantValid()) {
            throw new OA2GeneralError(OA2Errors.INVALID_GRANT, "invalid device code", HttpStatus.SC_BAD_REQUEST, null);
        }

        if (transaction == null || !transaction.isRFC8628Request()) {
            info("Attempt to access RFC8628 end point by client, but no pending devide flow found.");
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                    "no pending request", HttpStatus.SC_UNAUTHORIZED, null);
        }
        if (!transaction.getClient().getIdentifierString().equals(client.getIdentifierString())) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "wrong client, access denied",
                    HttpStatus.SC_UNAUTHORIZED, null);
        }
        RFC8628State rfc8628State = transaction.getRFC8628State();
        if (rfc8628State.isExpired()) {
            // Odd case that it has expired, but the garbage collector has not disposed of it yet, for whatever reason.
            throw new OA2ATException(OA2Errors.ACCESS_DENIED, DEVICE_CODE + " expired", HttpStatus.SC_UNAUTHORIZED, null);
        }

        if (rfc8628State.lastTry + rfc8628State.interval > now) {
            rfc8628State.lastTry = now;
            rfc8628State.interval = rfc8628State.interval + DEFAULT_WAIT;
            transaction.setRFC8628State(rfc8628State);
            getTransactionStore().save(transaction);
            throw new OA2ATException("slow_down", "slow down");
        }
        rfc8628State.lastTry = now;
        transaction.setRFC8628State(rfc8628State);
        String scope = getFirstParameterValue(request, SCOPE);
        if (!isTrivial(scope)) {
            // scope is optional, so only take notice if they send something
            TransactionState transactionState = new TransactionState(request, response, null, transaction);
            transaction.setScopes(ClientUtils.resolveScopes(transactionState, true));
        }

        getTransactionStore().save(transaction);

        if (!rfc8628State.valid) {
            throw new OA2ATException("authorization_pending", "authorization pending");
        }
        // If we make it this far, we just turn the entire thing over to the standard access token flow
        transaction.setAuthGrantValid(false);
        getTransactionStore().save(transaction);

        IssuerTransactionState issuerTransactionState = getIssuerTransactionState(
                request,
                response,
                authorizationGrant,
                transaction,
                true);
        doAT(issuerTransactionState, client);
        OA2SE oa2se = (OA2SE) getServiceEnvironment();
        VirtualOrganization vo = oa2se.getVO(transaction.getIdentifier());
        if (vo == null) {
            ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setJsonWebKey((oa2se).getJsonWebKeys().getDefault());
        } else {
            ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        writeATResponse(response, issuerTransactionState);

    }

    public static class TokenExchangeRecordRetentionPolicy extends SafeGCRetentionPolicy {
        public TokenExchangeRecordRetentionPolicy(String serviceAddress, boolean safeGC) {
            super(serviceAddress, safeGC);
        }

        @Override
        public boolean retain(Object key, Object value) {
            if (safeGCSkipIt(key.toString())) {
                return true;
            }
            // key is the identifier, values is the TXRecord
            TXRecord txr = (TXRecord) value;
            if (System.currentTimeMillis() <= txr.getExpiresAt()) {
                return true; // so keep it.
            }
            return false;
        }

        @Override
        public Map getMap() {
            // Don't need the map for the policy, so don't set it.
            return null;
        }

        @Override
        public boolean applies() {
            return true;
        }
    }

}
