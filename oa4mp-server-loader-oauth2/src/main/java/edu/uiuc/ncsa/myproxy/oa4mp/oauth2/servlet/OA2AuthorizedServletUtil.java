package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.UsernameFindable;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.security.delegation.server.request.AGRequest;
import edu.uiuc.ncsa.security.delegation.server.request.AGResponse;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTRunner;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.StringTokenizer;

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
    public OA2ServiceTransaction doDelegation(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
        OA2Client client = (OA2Client) servlet.getClient(req);

        try {
            String cid = "client=" + client.getIdentifier();
            DebugUtil.info(this, "2.a. Starting a new cert request: " + cid);
            servlet.checkClientApproval(client);
            AGResponse agResponse = (AGResponse) servlet.getAGI().process(new AGRequest(req, null));
            OA2ServiceTransaction transaction = createNewTransaction(agResponse.getGrant());
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
            servlet.getTransactionStore().save(transaction);
            DebugUtil.info(this, "Saved new transaction with id=" + transaction.getIdentifierString());

            Map<String, String> params = agResponse.getParameters();

            preprocess(new TransactionState(req, resp, params, transaction));
            DebugUtil.trace(this, "saved transaction for " + cid + ", trans id=" + transaction.getIdentifierString());

            agResponse.write(resp);
            DebugUtil.info(this, "2.b finished initial request for token =\"" + transaction.getIdentifierString() + "\".");

            postprocess(new IssuerTransactionState(req, resp, params, transaction, agResponse));
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
        ServletDebugUtil.printAllParameters(this.getClass(), httpServletRequest);
        String callback = httpServletRequest.getParameter(OA2Constants.REDIRECT_URI);
        if (httpServletRequest.getParameterMap().containsKey(OA2Constants.REQUEST_URI)) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_URI_NOT_SUPPORTED,
                    "Request uri not supported by this server",
                    httpServletRequest.getParameter(OA2Constants.STATE),
                    callback);
        }
        if (httpServletRequest.getParameterMap().containsKey(OA2Constants.REQUEST)) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED,
                    "Request not supported by this server",
                    httpServletRequest.getParameter(OA2Constants.STATE),
                    callback);
        }

        if (!httpServletRequest.getParameterMap().containsKey(OA2Constants.RESPONSE_TYPE)) {
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST,
                    "no response type",
                    httpServletRequest.getParameter(OA2Constants.STATE),
                    callback);
        }

        if(!httpServletRequest.getParameter(RESPONSE_TYPE).equals(RESPONSE_TYPE_CODE)){
            throw new OA2GeneralError(OA2Errors.UNSUPPORTED_RESPONSE_TYPE, "unsupported reponse type", HttpStatus.SC_BAD_REQUEST);
        }
        OA2ServiceTransaction t = CheckIdTokenHint(httpServletRequest, httpServletResponse, callback);
        if (t != null) {
            return t;
        }
        ServletDebugUtil.trace(this, "Starting doDelegation");
        t = doDelegation(httpServletRequest, httpServletResponse);
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        ServletDebugUtil.trace(this, "Starting done with doDelegation, creating claim util");
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t.getOA2Client().getConfig()));
        IDTokenHandler idTokenHandler = new IDTokenHandler(oa2SE, t, httpServletRequest);
        jwtRunner.addHandler(idTokenHandler);

        DebugUtil.trace(this, "starting to process claims, creating basic claims:");
        jwtRunner.doAuthClaims();

//        OA2ClaimsUtil claimsUtil = new OA2ClaimsUtil((OA2SE) servlet.getServiceEnvironment(), t);
//        claimsUtil.processAuthorizationClaims(httpServletRequest);
        //  servlet.getTransactionStore().save(t); // save the claims.
        DebugUtil.trace(this, "done with claims, transaction saved, claims = " + t.getClaims());
        return t;
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
            idToken = JWTUtil.verifyAndReadJWT(rawIDToken, ((OA2SE) servlet.getServiceEnvironment()).getJsonWebKeys());
        } catch (Throwable e) {
            throw new GeneralException("Error: Cannot read ID token hint", e);
        }
        String state = httpServletRequest.getParameter(STATE);
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
                        throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED, "Incorrect aud parameter in the ID token. This request is not supported on this server", state, callback);
                    }
                } else {
                    // The client that is associated with this user must be supplied.
                    throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED, "No aud parameter in the ID token. This request is not supported on this server", state, callback);
                }
                httpServletResponse.setStatus(HttpStatus.SC_OK);
                // The spec does not state that anything is returned, just a positive response.
                return t;

            }

        } catch (IOException e) {
            // Really something is probably wrong with the class structure is this fails...
            throw new NFWException("Internal error: Could not cast the store to a username findable store.");
        }


        throw new OA2RedirectableError(OA2Errors.LOGIN_REQUIRED, "Login required.", state, callback);
    }

    protected ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws UnsupportedEncodingException {
        AGResponse agResponse = (AGResponse) iResponse;
        Map<String, String> params = agResponse.getParameters();
        // Since the state (if present) has to be returned with any error message, we have to see if there is one
        // there first.
        String state = null;

        if (params.containsKey(STATE)) {
            state = params.get(STATE);
        }
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
        String rawRefreshLifetime = params.get(REFRESH_LIFETIME);
        if (rawRefreshLifetime != null && !rawRefreshLifetime.isEmpty()) {
            try {
                long rt = Long.parseLong(rawRefreshLifetime);
                st.setRefreshTokenLifetime(rt);
            } catch (Throwable t) {
                // do nothing.
            }

        }
        String nonce = params.get(NONCE);
        // FIX for OAUTH-180. Server must support clients that do not use a nonce. Just log it and rock on.
        if (nonce == null || nonce.length() == 0) {
            DebugUtil.info(this, "No nonce in initial request for " + client.getIdentifierString());
        } else {
            NonceHerder.putNonce(nonce); // Don't check it, just store it and return it later.
        }
        if (params.containsKey(DISPLAY)) {
            if (!params.get(DISPLAY).equals(DISPLAY_PAGE)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "Only " + DISPLAY + "=" + DISPLAY_PAGE + " is supported", state, givenRedirect);
            }
        }


        //OA2ServiceTransaction st = createNewTransaction(agResponse.getGrant());
        //st.setClient(agResponse.getClient());
        DebugUtil.info(this, "Created new unsaved transaction with id=" + st.getIdentifierString());
        Collection<String> scopes = resolveScopes(st, params, state, givenRedirect);
        st.setScopes(scopes);
        st.setAuthGrantValid(false);
        st.setAccessTokenValid(false);
        st.setCallback(URI.create(params.get(REDIRECT_URI)));
        // fine if the nonce is null or empty, just set what they sent.
        st.setNonce(nonce);
        // We can't support this because the spec says we must re-authenticate the user. We should have to track this
        // in all subsequent attempts. Since all requests have an expiration date, this parameter is redundant in any case.
        if (agResponse.getParameters().containsKey(OA2Constants.MAX_AGE)) {
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "The " + OA2Constants.MAX_AGE + " parameter is not supported at this time.", state, givenRedirect);
        }

        // Store the callback the user needs to use for this request, since the spec allows for many.
        // and now check for a bunch of stuff that might fail.

        checkPrompts(params);
        if (params.containsKey(REQUEST)) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_NOT_SUPPORTED, "The \"request\" parameter is not supported on this server", state, givenRedirect);
        }
        if (params.containsKey(REQUEST_URI)) {
            throw new OA2RedirectableError(OA2Errors.REQUEST_URI_NOT_SUPPORTED, "The \"request_uri\" parameter is not supported on this server", state, givenRedirect);
        }
        if (params.containsKey(RESPONSE_MODE)) {
            st.setResponseMode(params.get(RESPONSE_MODE));
        }

        return st;
    }

    protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
        return new OA2ServiceTransaction(grant);
    }

    /**
     * This method will take the scopes that the client sends in its request and inspect the scopes that it is allowed
     * to request. The result will be a list of permitted scopes. This is also where omitting the openid scope
     * causes the request to be rejected.
     *
     * @param st
     * @param params
     * @param state
     * @param givenRedirect
     * @return
     */
    protected Collection<String> resolveScopes(OA2ServiceTransaction st, Map<String, String> params, String state, String givenRedirect) {
        String rawScopes = params.get(SCOPE);

        DebugUtil.trace(this, ".resolveScopes: stored client scopes =" + ((OA2Client) st.getClient()).getScopes());
        DebugUtil.trace(this, ".resolveScopes: passed in scopes =" + rawScopes);
        DebugUtil.trace(this, ".resolveScopes: Scope util =" + OA2Scopes.ScopeUtil.getScopes());
        DebugUtil.trace(this, ".resolveScopes: server scopes=" + ((OA2SE) MyProxyDelegationServlet.getServiceEnvironment()).getScopes());
        if (rawScopes == null || rawScopes.length() == 0) {
            throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE, "Missing scopes parameter.", state, givenRedirect);
        }
        Collection<String> scopes = new ArrayList<>();

        OA2Client oa2Client = (OA2Client) st.getClient();
        // Fixes github issue 8, support for public clients: https://github.com/ncsa/OA4MP/issues/8
        if (oa2Client.isPublicClient()) {
            if (!oa2Client.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "Scopes must contain " + OA2Scopes.SCOPE_OPENID, state, givenRedirect);
            }
            // only allowed scope, regardless of what is requested.
            // This also covers the case of a client made with a full set of scopes, then
            // converted to a public client but the stored scopes are not updated.
            scopes.add(OA2Scopes.SCOPE_OPENID);
            DebugUtil.trace(this, ".resolveScopes: after resolution=" + scopes);
            return scopes;
        }
        StringTokenizer stringTokenizer = new StringTokenizer(rawScopes);
        boolean hasOpenIDScope = false;
        while (stringTokenizer.hasMoreTokens()) {
            String x = stringTokenizer.nextToken();
            if (!OA2Scopes.ScopeUtil.hasScope(x)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE, "Unrecognized scope \"" + x + "\"", state, givenRedirect);
            }
            if (x.equals(OA2Scopes.SCOPE_OPENID)) hasOpenIDScope = true;
            scopes.add(x);
        }
        Collection<String> storedClientScopes = oa2Client.getScopes();
        scopes = intersection(OA2Scopes.ScopeUtil.getScopes(), intersection(scopes, storedClientScopes));

        DebugUtil.trace(this, ".resolveScopes: after resolution=" + scopes);


        if (!hasOpenIDScope)
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "Scopes must contain " + OA2Scopes.SCOPE_OPENID, state, givenRedirect);
        return scopes;
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
    protected void checkPrompts(Map<String, String> map) {
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
            throw new OA2RedirectableError(OA2Errors.LOGIN_REQUIRED, "A login is required on this server", map.get(OA2Constants.STATE));
        }
        if (prompt.contains(PROMPT_NONE) && 1 < prompt.size()) {
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "You cannot specify \"none\" for the prompt and any other option", map.get(OA2Constants.STATE));
        }

        if (prompt.contains(PROMPT_LOGIN)) return;
        // CIL-737 fix: accept select_account
        if (prompt.contains(PROMPT_SELECT_ACCOUNT)) return;

        // At this point there is neither a "none" or a "login" and we don's support anything else.

        throw new OA2RedirectableError(OA2Errors.LOGIN_REQUIRED,
                "Only " + PROMPT + "=" + PROMPT_LOGIN + " or " + PROMPT_SELECT_ACCOUNT +
                        " are supported on this server.", map.get(OA2Constants.STATE));


    }

    /* *********
   Boiler plated code to make this work.
  */

    public void preprocess(TransactionState state) throws Throwable {
        state.getResponse().setHeader("X-Frame-Options", "DENY");
    }

    public void postprocess(TransactionState state) throws Throwable {
    }
    /* *******
    End boiler-plate
     */
}
