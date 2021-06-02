package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.UsernameFindable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AccessTokenConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.security.delegation.server.request.AGResponse;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTRunner;
import edu.uiuc.ncsa.security.oauth_2_0.server.AGIResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.server.AGRequest2;
import edu.uiuc.ncsa.security.oauth_2_0.server.RFC8693Constants;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet.getServiceEnvironment;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;

/**
 * This is set of calls to replace the old Authorized Servlet. It should be invoked by t
 * <p>Created by Jeff Gaynor<br>
 * on 5/14/18 at  12:14 PM
 */
public class OA2AuthorizedServletUtil {
    protected MyProxyDelegationServlet servlet = null;

    public OA2AuthorizedServletUtil(MyProxyDelegationServlet servlet) {
        this.servlet = servlet;
    }

    public OA2ServiceTransaction doDelegation(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
    return doDelegation(req,resp, false); // Default operation for all of OA4MP.
    }

    /**
     * Main entry point for this class. Call this. It does <b>not</b> do claims processing. That is done in the
     * {@link OA2AuthorizationServer#createRedirect(HttpServletRequest, HttpServletResponse, ServiceTransaction)}
     * which is the last possible point to do it.
     *
     * @param req
     * @param resp
     * @return
     * @throws Throwable
     */
    public OA2ServiceTransaction doDelegation(HttpServletRequest req, HttpServletResponse resp, boolean encodeTokenInResponse) throws Throwable {
        OA2Client client;
        try {
            client = (OA2Client) servlet.getClient(req);
        } catch (UnknownClientException ukc) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT
                    , "unknown client",
                    HttpStatus.SC_BAD_REQUEST, null);
        }
        OA2SE oa2se = (OA2SE) getServiceEnvironment();
        basicChecks(req); // Checks response type, code and such

        try {
            String cid = "client=" + client.getIdentifier();
            DebugUtil.info(this, "2.a. Starting a new cert request: " + cid);
            servlet.checkClientApproval(client);
            // Generally the lifetime of an authorization grant is a matter of server policy, not a client request.
            AGRequest2 agRequest2 = new AGRequest2(req, oa2se.getAuthorizationGrantLifetime());
            //agRequest2.setEncodeToken(encodeTokenInResponse);
            AGIResponse2 agResponse = (AGIResponse2) servlet.getAGI().process(agRequest2);
            agResponse.setEncodeToken(encodeTokenInResponse);
            OA2ServiceTransaction transaction = createNewTransaction(agResponse.getGrant());
            transaction.setAuthGrantLifetime(oa2se.getAuthorizationGrantLifetime()); // make sure these match.
            String requestState = req.getParameter(OA2Constants.STATE);
            transaction.setRequestState(requestState);
            /*
            Fixes CIL-644
            Extended attribute support means that a client may send fully qualifies (FQ) request parameters
            e.g. of the form oa4mp:/req/role and these will be stashed for later processing
            (most likely by a script, so we can avoid server changes). Nothing is done with these here, they
            are stashed and forwarded at the correct time.
             */
            if (client.hasExtendedAttributeSupport()) {
                ExtendedParameters xp = new ExtendedParameters();
                // Take the parameters and parse them into configuration objects,
                JSONObject extAttr = xp.snoopParameters(req.getParameterMap());
                if (extAttr != null && !extAttr.isEmpty()) {
                    transaction.setExtendedAttributes(extAttr);
                }
            }
            agResponse.setServiceTransaction(transaction);
            transaction.setClient(client);
            transaction = (OA2ServiceTransaction) verifyAndGet(agResponse);
            transaction.setAuthTime(new Date()); // have to set the time to now.
            DebugUtil.info(this, "Saved new transaction with id=" + transaction.getIdentifierString());

            Map<String, String> params = agResponse.getParameters();

            preprocess(new TransactionState(req, resp, params, transaction));
            DebugUtil.trace(this, "saved transaction for " + cid + ", trans id=" + transaction.getIdentifierString());

            DebugUtil.info(this, "2.b finished initial request for token =\"" + transaction.getIdentifierString() + "\".");

            postprocess(new IssuerTransactionState(req, resp, params, transaction, agResponse));
            servlet.getTransactionStore().save(transaction);
            agResponse.write(resp);
            return transaction;
        } catch (Throwable t) {
            if (t instanceof UnapprovedClientException) {
                DebugUtil.warn(this, "Unapproved client: " + client.getIdentifierString());
            }
            throw t;
        }
    }

    /**
     * Note the at the entry point for this is the {@link #doIt(HttpServletRequest, HttpServletResponse)} method
     * if authorization is done elsewhere (so the assumption is that authorization has already happened),
     * vs. the doDelegation call that is invoked by the OA4MP Authorize servlet. The difference is
     * that the two paths will invoke the claims processing at different points.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @return
     * @throws Throwable
     */
    protected OA2ServiceTransaction doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        String rawcb = basicChecks(httpServletRequest);
        OA2ServiceTransaction t = CheckIdTokenHint(httpServletRequest, httpServletResponse, rawcb);
        if (t != null) {
            // In this case, there is an id token hint, so processing changes.
            return t;
        }
        ServletDebugUtil.trace(this, "Starting doDelegation");
        t = doDelegation(httpServletRequest, httpServletResponse);
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        ServletDebugUtil.trace(this, "Starting done with doDelegation, creating claim util");
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, t.getOA2Client().getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, t, httpServletRequest);

        DebugUtil.trace(this, "starting to process claims, creating basic claims:");
        try {
            jwtRunner.doAuthClaims();
        } catch (IllegalAccessException iax) {
            oa2SE.getTransactionStore().save(t); // save it so we have this in the future, then bail
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                    "access denied",
                    HttpStatus.SC_UNAUTHORIZED,
                    t.getRequestState(),
                    t.getCallback());

        }
        if (!t.getFlowStates().acceptRequests || t.getFlowStates().getClaims) {
            // if they are not allowed to get claims, they get booted out here
            oa2SE.getTransactionStore().save(t); // save it so we have this in the future, then bail
            throw new OA2RedirectableError(OA2Errors.ACCESS_DENIED,
                    "access denied",
                    HttpStatus.SC_UNAUTHORIZED,
                    t.getRequestState(),
                    t.getCallback());
        }
        DebugUtil.trace(this, "done with claims, transaction saved, claims = " + t.getUserMetaData());
        return t;
    }

    private String basicChecks(HttpServletRequest httpServletRequest) {
        ServletDebugUtil.printAllParameters(this.getClass(), httpServletRequest);
        String requestState = httpServletRequest.getParameter(OA2Constants.STATE);
        String rawcb = httpServletRequest.getParameter(OA2Constants.REDIRECT_URI);
        try {
            URI.create(rawcb); // check they didn't send us garbage
        } catch (Throwable t) {
            throw new OA2GeneralError(
                    OA2Errors.REQUEST_URI_NOT_SUPPORTED,
                    "redirect is not a valid uri",
                    HttpStatus.SC_BAD_REQUEST,
                    requestState
            );

        }
        // The request state needs to be set as early as possible since it is used to construct
        // any error messages.
        // Note that even though we have a callback, we are not far enough along yet to look in
        // the client configuration and see if it is valid, so we cannot use it.
        if (httpServletRequest.getParameterMap().containsKey(OA2Constants.REQUEST_URI)) {
            throw new OA2GeneralError(
                    OA2Errors.REQUEST_URI_NOT_SUPPORTED,
                    "Request uri not supported by this server",
                    HttpStatus.SC_BAD_REQUEST,
                    requestState);
        }
        if (httpServletRequest.getParameterMap().containsKey(OA2Constants.REQUEST)) {
            throw new OA2GeneralError(OA2Errors.REQUEST_NOT_SUPPORTED,
                    "Request not supported by this server",
                    HttpStatus.SC_BAD_REQUEST,
                    requestState);
        }

        if (!httpServletRequest.getParameterMap().containsKey(OA2Constants.RESPONSE_TYPE)) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    " The " + RESPONSE_TYPE + " is missing from the request.",
                    HttpStatus.SC_BAD_REQUEST,
                    requestState);
        }

        if (!httpServletRequest.getParameter(RESPONSE_TYPE).equals(RESPONSE_TYPE_CODE)) {
            throw new OA2GeneralError(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                    "The given " + RESPONSE_TYPE + " is not supported.",
                    HttpStatus.SC_BAD_REQUEST,
                    requestState);
        }
        return rawcb;
    }

    /**
     * In this case, a previous request to the token endpoint returned an ID token. If this is sent to
     * this endpoint, we are to check that there is an active logon for the user (=there is a transaction
     * for that name here) and return a success but no body. Otherwise, we throw an exception.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @param callback
     * @return
     */
    protected OA2ServiceTransaction CheckIdTokenHint(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, String callback) {
        if (!httpServletRequest.getParameterMap().containsKey(ID_TOKEN_HINT)) {
            return null;
        }
        UsernameFindable ufStore = null;
        String rawIDToken = String.valueOf(httpServletRequest.getParameterMap().get(ID_TOKEN_HINT));
        JSONObject idToken = null;
        try {
            idToken = JWTUtil.verifyAndReadJWT(rawIDToken, ((OA2SE) getServiceEnvironment()).getJsonWebKeys());
        } catch (Throwable e) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "cannot read ID token hint",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }

        String username = null;
        if (idToken.containsKey(OA2Claims.SUBJECT)) {
            username = idToken.getString(OA2Claims.SUBJECT);
        } else {

        }
        try {

            ufStore = (UsernameFindable) servlet.getTransactionStore();
            OA2ServiceTransaction t = ufStore.getByUsername(username);

            if (t != null) {
                // Then there is a transaction, so the user authenticated successfully.
                if (idToken.containsKey(OA2Claims.AUDIENCE)) {
                    if (!t.getClient().getIdentifierString().equals(idToken.getString(OA2Claims.AUDIENCE))) {
                        // The wrong client for this user is attempting the request. That is not allowed.
                        throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED,
                                "Incorrect aud parameter in the ID token. This request is not supported on this server",
                                HttpStatus.SC_BAD_REQUEST,
                                t.getRequestState(),
                                t.getCallback());
                    }
                } else {
                    // The client that is associated with this user must be supplied.
                    throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED,
                            "No aud parameter in the ID token. This request is not supported on this server",
                            HttpStatus.SC_BAD_REQUEST,
                            t.getRequestState(),
                            t.getCallback());
                }
                httpServletResponse.setStatus(HttpStatus.SC_OK);
                // The spec does not state that anything is returned, just a positive response.
                return t;

            }

        } catch (IOException e) {
            // Really something is probably wrong with the class structure is this fails...
            throw new NFWException("Internal error: Could not cast the store to a username findable store.");
        }

        // Something is wrong with the request, so just bomb.
        throw new OA2GeneralError(OA2Errors.LOGIN_REQUIRED,
                "Login required.",
                HttpStatus.SC_UNAUTHORIZED,
                null);
    }

    protected ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws UnsupportedEncodingException {
        AGResponse agResponse = (AGResponse) iResponse;
        Map<String, String> params = agResponse.getParameters();
        // Since the state (if present) has to be returned with any error message, we have to see if there is one
        // there first. We do not store the state.
        OA2ServiceTransaction st = (OA2ServiceTransaction) agResponse.getServiceTransaction();
        //Spec says that the redirect must match one of the ones stored and if not, the request is rejected.
        String givenRedirect = params.get(REDIRECT_URI);
        OA2Client client = st.getOA2Client();
        OA2ClientUtils.check(client, givenRedirect);
        // by this point it has been verified that the redirect uri is valid.

        String rawSecret = params.get(CLIENT_SECRET);
        if (rawSecret != null) {
            DebugUtil.info(this, "Client is sending secret in initial request. Though not forbidden by the protocol this is discouraged.");
            if (!client.getSecret().equals(rawSecret)) {
                DebugUtil.info(this, "And for what it is worth, the client sent along an incorrect secret too...");
            }
        }
        String rawATLifetime = params.get(ACCESS_TOKEN_LIFETIME);
        if (!isTrivial(rawATLifetime)) {

            try {
                long at = ConfigUtil.getValueSecsOrMillis(rawATLifetime);
                //               long at = Long.parseLong(rawATLifetime);
                st.setRequestedATLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set request access token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        String rawRefreshLifetime = params.get(REFRESH_LIFETIME);
        if (!isTrivial(rawRefreshLifetime)) {
            try {
                long rt = ConfigUtil.getValueSecsOrMillis(rawRefreshLifetime);
                //long rt = Long.parseLong(rawRefreshLifetime);
                st.setRequestedRTLifetime(rt);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set request refresh token lifetime to \"" + rawRefreshLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }

        }
        String nonce = params.get(NONCE);
        // FIX for OAUTH-180. Server must support clients that do not use a nonce. Just log it and rock on.
        if (nonce == null || nonce.length() == 0) {
            DebugUtil.info(this, "No nonce in initial request for " + client.getIdentifierString());
        }
        NonceHerder.putNonce(nonce);
      /*  This checks that nonces are not re-used. Used to check for them,
          but not now. Just store it for returning later in the ID token.
      try {
            NonceHerder.checkNonce(nonce);
        }catch(InvalidNonceException ine){
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "invalid nonce",
                    HttpStatus.SC_BAD_REQUEST,
                    st.getRequestState());
        }*/


        if (params.containsKey(DISPLAY)) {
            if (!params.get(DISPLAY).equals(DISPLAY_PAGE)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                        "Only " + DISPLAY + "=" + DISPLAY_PAGE + " is supported",
                        HttpStatus.SC_BAD_REQUEST,
                        st.getRequestState(),
                        st.getCallback());
            }
        }


        //OA2ServiceTransaction st = createNewTransaction(agResponse.getGrant());
        //st.setClient(agResponse.getClient());
        DebugUtil.info(this, "Created new unsaved transaction with id=" + st.getIdentifierString());

        st.setAuthGrantValid(false);
        st.setAccessTokenValid(false);
        st.setCallback(URI.create(params.get(REDIRECT_URI)));
        // fine if the nonce is null or empty, just set what they sent.
        st.setNonce(nonce);
        // We can't support this because the spec says we must re-authenticate the user. We should have to track this
        // in all subsequent attempts. Since all requests have an expiration date, this parameter is redundant in any case.
        if (agResponse.getParameters().containsKey(OA2Constants.MAX_AGE)) {
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                    "The " + OA2Constants.MAX_AGE + " parameter is not supported at this time.",
                    HttpStatus.SC_BAD_REQUEST,
                    st.getRequestState(),
                    st.getCallback());
        }

        // Store the callback the user needs to use for this request, since the spec allows for many.
        // and now check for a bunch of stuff that might fail.

        checkPrompts(st, params);
        if (params.containsKey(REQUEST)) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED,
                    REQUEST + " not supported on this server",
                    HttpStatus.SC_BAD_REQUEST,
                    st.getRequestState(),
                    st.getCallback());
        }
        if (params.containsKey(REQUEST_URI)) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_URI_NOT_SUPPORTED,
                    REQUEST_URI + " not supported on this server",
                    HttpStatus.SC_BAD_REQUEST,
                    st.getRequestState(),
                    st.getCallback());
        }
        if (params.containsKey(RESPONSE_MODE)) {
            st.setResponseMode(params.get(RESPONSE_MODE));
        }
        // NOTE that the audience is set in the postprocess call. Might move it here...
        return st;
    }

    protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
        return new OA2ServiceTransaction(grant);
    }


    /**
     * Utility call to return the intersection of two lists of strings.
     *
     * @param x
     * @param y
     * @return
     */
    protected static Collection<String> intersection(Collection<String> x, Collection<String> y) {
        ArrayList<String> output = new ArrayList<>();
        for (String val : x) {
            if (y.contains(val)) {
                output.add(val);
            }
        }
        return output;
    }

    /**
     * Basically, if the prompt parameter is there, we only support the login option.
     *
     * @param map
     */
    protected void checkPrompts(OA2ServiceTransaction transaction, Map<String, String> map) {
        if (!map.containsKey(PROMPT)) return;  //nix to do
        String prompts = map.get(PROMPT);
        // now we have to see what is in it.
        StringTokenizer st = new StringTokenizer(prompts);
        ArrayList<String> prompt = new ArrayList<>();

        while (st.hasMoreElements()) {
            prompt.add(st.nextToken());
        }
        // CIL-91 if prompt = none is passed in, return an error with login_required as the message.
        if (!prompt.contains(PROMPT_NONE) && prompt.size() == 0) {
            throw new OA2RedirectableError(OA2Errors.LOGIN_REQUIRED,
                    "A login is required on this server",
                    HttpStatus.SC_BAD_REQUEST,
                    map.get(OA2Constants.STATE));
        }
        if (prompt.contains(PROMPT_NONE) && 1 < prompt.size()) {
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                    "You cannot specify \"none\" for the prompt and any other option",
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState(),
                    transaction.getCallback());
        }

        if (prompt.contains(PROMPT_LOGIN)) return;
        // CIL-737 fix: accept select_account
        if (prompt.contains(PROMPT_SELECT_ACCOUNT)) return;

        // At this point there is neither a "none" or a "login" and we don's support anything else.

        throw new OA2RedirectableError(OA2Errors.LOGIN_REQUIRED,
                "Only " + PROMPT + "=" + PROMPT_LOGIN + " or " + PROMPT_SELECT_ACCOUNT +
                        " are supported on this server.",
                HttpStatus.SC_BAD_REQUEST,
                transaction.getRequestState(),
                transaction.getCallback()
        );


    }

    /* *********
   Boiler plated code to make this work.
  */

    public void preprocess(TransactionState state) throws Throwable {
        //  state.getResponse().setHeader("X-Frame-Options", "DENY");
    }

    /* *******
    End boiler-plate
     */

    /**
     * <h3>RFC 8707 support.</h3>
     * Internally we call it audience (since the aud claim is returned),
     * but the difference is that a resource is a list of URIs and the audience is
     * a list of logical names or URIs.
     * Generally we  encourage people to just use
     * the resource parameter. <br/><br/>
     *
     * <b>Especial note:</b> The resource and audience configuration lives in the access token
     * configuration of the client.<br/><br/>
     *
     * According to 2.1 in RFC 8707: <br/>
     * "In the code flow (Section 4.1 of OAuth 2.0 [RFC6749]) where an intermediate
     *   representation of the authorization grant (the authorization code) is
     *   returned from the authorization endpoint, the requested resource is
     *   applicable to the full authorization grant."
     *  <br/><br/>
     * We return these in the access token. We do allow that the user can pass these in
     * as part of the authorization request, but merely record the fact for the access
     * token, since we do not have some use of resource/audience for authorization grants.
     * The spec simply (seems) to state that if it is present in the auth request, it should
     * apply to that too.
     * @param state
     */
    public void figureOutAudienceAndResource(TransactionState state) {
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();

        String[] rawResource = state.getRequest().getParameterValues(RFC8693Constants.RESOURCE);
        String[] rawAudience = state.getRequest().getParameterValues(RFC8693Constants.AUDIENCE);

        if (rawResource == null && rawAudience == null) {
            // implies there is no such parameters.
            return; // nothing to do.
        }

        ServletDebugUtil.trace(this, "raw audience = " + rawAudience);
        ServletDebugUtil.trace(this, "raw resource = " + rawResource);

        LinkedList<String> resource = new LinkedList<>();
        LinkedList<String> audience = new LinkedList<>();

        if (rawResource != null) {
            for (String r : rawResource) {
                try {
                    URI uri = URI.create(r);
                    resource.add(r);
                    if (!uri.isAbsolute()) {
                        throw new OA2GeneralError(OA2Errors.INVALID_TARGET,
                                "Only absolute uris are allowed",
                                HttpStatus.SC_BAD_REQUEST,
                                t.getRequestState());
                    }
                    if (!StringUtils.isTrivial(uri.getFragment())) {
                        throw new OA2GeneralError(OA2Errors.INVALID_TARGET,
                                "Fragments are not allowed",
                                HttpStatus.SC_BAD_REQUEST,
                                t.getRequestState());
                    }
                } catch (Throwable throwable) {
                    // skip it
                }
            }
        }

        if (rawAudience != null) {
            for (String a : rawAudience) {
                audience.add(a);
            }
        }

             /*
             Scorecard: the client can request either resources (URIs for the audience claim) or audiences (which
             are logical names for the audience claim). This is truly annoying since both end up in the same
             claim, but do very different things. Templates are stored by either.
              */
        if (resource.size() == 0 && audience.size() == 0) {
            // try to special case it
            OA2Client client = (OA2Client) t.getClient();
            AccessTokenConfig atCfg = client.getAccessTokensConfig();

            if (atCfg.getTemplates().size() == 1) {
                // Special case. They have configured exactly one audience claim, so they may omit it and we
                // will pull it out of their configuration and supply it. They do not need to
                // send it along in the request. This fails if they ever configure a second template though (as it should).
                String x = atCfg.getAudience().iterator().next();
                try {
                    URI.create(x);
                    resource.add(x);
                } catch (Throwable throwable) {
                    audience.add(x);
                }
            } else {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "missing audience request",
                        HttpStatus.SC_BAD_REQUEST,
                        t.getRequestState());
            }
        }
        // One of these may be empty.
        t.setResource(resource);
        t.setAudience(audience);

    }

    protected Collection<String> resolveScopes(TransactionState transactionState) {
        return ClientUtils.resolveScopes(transactionState, false);
    }

    public void postprocess(TransactionState transactionState) {
        // Order of operations: The audience and resources must be determined before the scopes can
        // be resolved since they are required for that and this bit must be done as the absolutely last thing.
        figureOutAudienceAndResource(transactionState);
        OA2ServiceTransaction t = (OA2ServiceTransaction) transactionState.getTransaction();
        Collection<String> scopes = resolveScopes(transactionState);
        t.setScopes(scopes);
        transactionState.getResponse().setHeader("X-Frame-Options", "DENY");

        //t.setScopes(scopes);
    }
}
