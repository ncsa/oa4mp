package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ClaimSourceFactoryImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAccessTokenServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.*;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATIResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.server.RTI2;
import edu.uiuc.ncsa.security.oauth_2_0.server.RTIRequest;
import edu.uiuc.ncsa.security.oauth_2_0.server.RTIResponse;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceFactory;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  2:03 PM
 */
public class OA2ATServlet extends AbstractAccessTokenServlet {
    @Override
    public void preprocess(TransactionState state) throws Throwable {
        super.preprocess(state);
        state.getResponse().setHeader("Cache-Control", "no-store");
        state.getResponse().setHeader("Pragma", "no-cache");

        OA2ServiceTransaction st = (OA2ServiceTransaction) state.getTransaction();
        Map<String, String> p = state.getParameters();
        String givenRedirect = p.get(OA2Constants.REDIRECT_URI);
        try {
            st.setCallback(URI.create(givenRedirect));
        } catch (Throwable t) {
            throw new InvalidURIException("Invalid redirect URI \"" + givenRedirect + "\"", t);
        }
        //Spec says that the redirect must match one of the ones stored and if not, the request is rejected.
        OA2ClientCheck.check(st.getClient(), givenRedirect);
        // Store the callback the user needs to use for this request, since the spec allows for many.

        // If there is a nonce in the initial request, it must be returned as part of the access token
        // response to prevent replay attacks.
        // Here is where we put the information from the session for generating claims in the id_token
        if (st.getNonce() != null && 0 < st.getNonce().length()) {
            p.put(OA2Constants.NONCE, st.getNonce());
        }

        p.put(OA2Constants.CLIENT_ID, st.getClient().getIdentifierString());
        populateClaims(state.getRequest(), p, st);
    }

    protected Map<String, String> populateClaims(HttpServletRequest request, Map<String, String> p, OA2ServiceTransaction st) {
        OA2SE oa2se = (OA2SE) getServiceEnvironment();
        String issuer = null;
        // So in order
        // 1. get the issuer from the admin client
        List<Identifier> admins = oa2se.getPermissionStore().getAdmins(st.getClient().getIdentifier());

        for (Identifier adminID : admins) {
            AdminClient ac = oa2se.getAdminClientStore().get(adminID);
            if (ac != null) {
                if (ac.getIssuer() != null) {
                    issuer = ac.getIssuer();
                    break;
                }
            }
        }
        // 2. If the admin client does not have an issuer set, see if the client has one
        if (issuer == null) {
            issuer = ((OA2Client) st.getClient()).getIssuer();
        }

        // 3. If the client does not have one, see if there is a server default to use
        // The discovery servlet will try to use the server default or construct the issuer
        if (issuer == null) {
            issuer = OA2DiscoveryServlet.getIssuer(request);
        }
        p.put(OA2Claims.ISSUER, issuer);

        p.put(OA2Claims.SUBJECT, st.getUsername());
        if (st.hasAuthTime()) {
            // convert the date to a time if needed.
            p.put(OA2Constants.AUTHORIZATION_TIME, Long.toString(st.getAuthTime().getTime() / 1000));
        }
        return p;
    }

    /**
     * The lifetime of the refresh token. This is the non-zero minimum of the client's requested
     * lifetime, the user's request at authorization time and the server global limit.
     *
     * @param st2
     * @return
     */
    protected long computeRefreshLifetime(OA2ServiceTransaction st2) {
        OA2Client client = (OA2Client) st2.getClient();
        long lifetime = Math.max(st2.getRefreshTokenLifetime(), client.getRtLifetime());

        OA2SE oa2SE = (OA2SE) getServiceEnvironment();
        if (oa2SE.getRefreshTokenLifetime() <= 0) {
            throw new NFWException("Internal error: the server-wide default for the refresh token lifetime has not been set.");
        }
        lifetime = Math.min(lifetime, oa2SE.getRefreshTokenLifetime());
        return lifetime;

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

        OA2Client client = (OA2Client) getClient(request);

        if (grantType.equals(OA2Constants.REFRESH_TOKEN)) {
            String rawSecret = getClientSecret(request);
            if (!client.isPublicClient()) {
                // if there is a secret, verify it.
                verifyClientSecret(client, rawSecret);
            }
            doRefresh(client, request, response);
            return true;
        }
        if (grantType.equals(OA2Constants.AUTHORIZATION_CODE_VALUE)) {
            // public clients cannot get an access token
            IssuerTransactionState state = doAT(request, response, client);
            ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
            OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
            atResponse.setClaims(t.getClaims());
            atResponse.write(response);
            return true;
        }

        return false;
    }

    @Override
    protected void doIt(HttpServletRequest request, HttpServletResponse response) throws Throwable {
        printAllParameters(request);
        String grantType = getFirstParameterValue(request, OA2Constants.GRANT_TYPE);
        if (isEmpty(grantType)) {
            warn("Error servicing request. No grant type was given. Rejecting request.");
            throw new GeneralException("Error: Could not service request");
        }
        if (executeByGrant(grantType, request, response)) {
            return;
        }
        warn("Error: grant type was not recognized. Request rejected.");
        throw new ServletException("Error: Unknown request type.");
    }

    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        verifyClientSecret(client, getClientSecret(request));
        IssuerTransactionState state = doDelegation(client, request, response);
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        atResponse.setSignToken(client.isSignTokens());
        OA2ServiceTransaction st2 = (OA2ServiceTransaction) state.getTransaction();
        if (!st2.getFlowStates().acceptRequests || !st2.getFlowStates().accessToken) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "getting access token denied", HttpStatus.SC_UNAUTHORIZED);
        }
        atResponse.setClaims(st2.getClaims());
        DebugUtil.dbg(this, "set token signing flag =" + atResponse.isSignToken());
        if (!client.isRTLifetimeEnabled() && ((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled()) {
            // Since this bit of information could be extremely useful if a service decides
            // eto start issuing refresh tokens after
            // clients have been registered, it should be logged.
            info("Refresh tokens are disabled for client " + client.getIdentifierString() + ", but enabled on the server. No refresh token will be madeg.");
        }
        if (client.isRTLifetimeEnabled() && ((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled()) {

            RefreshToken rt = atResponse.getRefreshToken();
            st2.setRefreshToken(rt);
            // First pass through the system should have the system default as the refresh token lifetime.
            st2.setRefreshTokenLifetime(((OA2SE) getServiceEnvironment()).getRefreshTokenLifetime());
            rt.setExpiresIn(computeRefreshLifetime(st2));
            st2.setRefreshTokenValid(true);
        } else {
            // Do not return a refresh token.
            atResponse.setRefreshToken(null);
        }

        getTransactionStore().save(st2);
        return state;
    }

    /**
     * This either peels the secret off the parameter list if it is there or from the headers. It
     * merely returns the raw string that is the secret. No checking against a client is done.
     * Also, a null is a perfectly acceptable return value if there is no secret, e.g. the client is public.
     *
     * @param request
     * @return
     */
    protected String getClientSecret(HttpServletRequest request) {
        String rawSecret = null;
        // Fix for CIL-430. Check the header and decode as needed.
        if (HeaderUtils.hasBasicHeader(request)) {
            DebugUtil.dbg(this, "doIt: Got the header.");
            try {
                rawSecret = HeaderUtils.getSecretFromHeaders(request);
            } catch (UnsupportedEncodingException e) {
                throw new NFWException("Error: internal use of UTF-8 encoding failed");
            }

        } else {
            DebugUtil.dbg(this, "doIt: no header for authentication, looking at parameters.");
            rawSecret = getFirstParameterValue(request, CLIENT_SECRET);

        }

        return rawSecret;
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
        }
        // we have to check that if we get both of these they refer to the same client, so someone
        // cannot hijack the session
        if (paramID == null) {
            if (headerID == null) {
                throw new UnknownClientException("Error: no client identifier given");
            }
            client = (OA2Client) getClient(headerID);
        } else {
            if (headerID == null) {
                client = (OA2Client) getClient(paramID);
            } else {
                if (!paramID.equals(headerID)) {
                    throw new UnknownClientException("Error: Too many client identifiers. Cannot resolve client");
                }
                client = (OA2Client) getClient(paramID); // doesn't matter which id we use since they are equal.
            }
        }

        checkClientApproval(client);


        return client;
    }

    protected void verifyClientSecret(OA2Client client, String rawSecret) {
        // Fix for CIL-332
        if (rawSecret == null) {
            // check headers.
            DebugUtil.dbg(this, "doIt: no secret, throwing exception.");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "Missing secret");
        }
        if (!client.getSecret().equals(DigestUtils.shaHex(rawSecret))) {
            DebugUtil.dbg(this, "doIt: bad secret, throwing exception.");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "Incorrect secret");
        }

    }

    protected OA2ServiceTransaction getByRT(RefreshToken refreshToken) throws IOException {
        if (refreshToken == null) {
            throw new GeneralException("Error: null refresh token encountered.");
        }
        RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
        return rts.get(refreshToken);
    }

    protected OA2TokenForge getTF2() {
        return (OA2TokenForge) getServiceEnvironment().getTokenForge();
    }

    protected TransactionState doRefresh(OA2Client c, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        RefreshToken oldRT = getTF2().getRefreshToken(request.getParameter(OA2Constants.REFRESH_TOKEN));
        if (c == null) {
            throw new InvalidTokenException("Could not find the client associated with refresh token \"" + oldRT + "\"");
        }

        OA2ServiceTransaction t = getByRT(oldRT);
        if (!t.getFlowStates().acceptRequests || !t.getFlowStates().refreshToken) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "refresh token access denied", HttpStatus.SC_UNAUTHORIZED);

        }
        if ((!((OA2SE) getServiceEnvironment()).isRefreshTokenEnabled()) || (!c.isRTLifetimeEnabled())) {
            throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED, "Refresh tokens are not supported on this server");
        }

        if (t == null || !t.isRefreshTokenValid()) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "Error: The refresh token is no longer valid.");
        }
        t.setRefreshTokenValid(false); // this way if it fails at some point we know it is invalid.
        AccessToken at = t.getAccessToken();
        RTIRequest rtiRequest = new RTIRequest(request, c, at);
        RTI2 rtIsuuer = new RTI2(getTF2(), getServiceEnvironment().getServiceAddress());
        RTIResponse rtiResponse = (RTIResponse) rtIsuuer.process(rtiRequest);
        rtiResponse.setSignToken(c.isSignTokens());
        rtiResponse.setClaims(t.getClaims());
        populateClaims(request, rtiResponse.getParameters(), t);
        RefreshToken rt = rtiResponse.getRefreshToken();
        rt.setExpiresIn(computeRefreshLifetime(t));
        t.setRefreshToken(rtiResponse.getRefreshToken());
        t.setRefreshTokenValid(true);
        t.setAccessToken(rtiResponse.getAccessToken());
        // At this point, key in the transaction store is the grant, so changing the access token
        // over-writes the current value. This practically invalidates the previous access token.
        getTransactionStore().remove(t.getIdentifier()); // this is necessary to clear any caches.
        ArrayList<String> targetScopes = new ArrayList<>();
        OA2SE oa2SE = (OA2SE) getServiceEnvironment();

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

        //    rtiResponse.setClaimSources(setupClaimSources(t, oa2SE));

        rtiResponse.setServiceTransaction(t);
        rtiResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        rtiResponse.setClaims(t.getClaims());
        getTransactionStore().save(t);
        rtiResponse.write(response);
        IssuerTransactionState state = new IssuerTransactionState(
                request,
                response,
                rtiResponse.getParameters(),
                t,
                rtiResponse);
        return state;
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {

        ATIResponse2 atResponse = (ATIResponse2) iResponse;

        TransactionStore transactionStore = getTransactionStore();
        BasicIdentifier basicIdentifier = new BasicIdentifier(atResponse.getParameters().get(OA2Constants.AUTHORIZATION_CODE));
        DebugUtil.dbg(this, "getting transaction for identifier=" + basicIdentifier);
        OA2ServiceTransaction transaction = (OA2ServiceTransaction) transactionStore.get(basicIdentifier);
        if (transaction == null) {
            // Then this request does not correspond to an previous one and must be rejected asap.
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "No pending transaction found for id=" + basicIdentifier);
        }
        if (!transaction.isAuthGrantValid()) {
            String msg = "Error: Attempt to use invalid authorization code.  Request rejected.";
            warn(msg);
            throw new GeneralException(msg);
        }

        boolean uriOmittedOK = false;
        if (!atResponse.getParameters().containsKey(OA2Constants.REDIRECT_URI)) {
            // OK, the spec states that if we get to this point (so the redirect URI has been verified) a client with a
            // **single** registered redirect uri **MAY** be omitted. It seems that various python libraries do not
            // send it in this case, so we have the option to accept or reject the request.
            if (((OA2Client) transaction.getClient()).getCallbackURIs().size() == 1) {
                uriOmittedOK = true;
            } else {
                throw new GeneralException("Error: No redirect URI. Request rejected.");
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
        /* Now we have to determine which scopes to return
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
        atResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        atResponse.setClaims(transaction.getClaims());
        // Need to do some checking but for now, just return transaction
        //return null;
        return transaction;
    }

    public static LinkedList<ClaimSource> setupClaimSources(OA2ServiceTransaction transaction, OA2SE oa2SE) {
        LinkedList<ClaimSource> scopeHandlers = new LinkedList<>();
        DebugUtil.dbg(OA2ATServlet.class, "setting up claim sources");
        if (oa2SE.getClaimSource() != null && oa2SE.getClaimSource().isEnabled()) {
            DebugUtil.dbg(OA2ATServlet.class, "Adding default claim source.");

            scopeHandlers.add(oa2SE.getClaimSource());
        }
        ClaimSourceFactory oldSHF = ClaimSourceFactoryImpl.getFactory();
        ClaimSourceFactoryImpl.setFactory(new ClaimSourceFactoryImpl());

        OA2Client client = (OA2Client) transaction.getClient();
        DebugUtil.dbg(OA2ATServlet.class, "Getting configured claim source factory " + ClaimSourceFactoryImpl.getFactory().getClass().getSimpleName());
        DebugUtil.dbg(OA2ATServlet.class, "Adding other claim sources");

        scopeHandlers.addAll(ClaimSourceFactoryImpl.createClaimSources(oa2SE, client));
        DebugUtil.dbg(OA2ATServlet.class, "Total claim source count = " + scopeHandlers.size());

        ClaimSourceFactoryImpl.setFactory(oldSHF);
        return scopeHandlers;
    }
}
