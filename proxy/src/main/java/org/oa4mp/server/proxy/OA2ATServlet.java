package org.oa4mp.server.proxy;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.servlet.HeaderUtils;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.common.servlet.TransactionState;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.RefreshToken;
import org.oa4mp.delegation.common.token.impl.*;
import org.oa4mp.delegation.server.*;
import org.oa4mp.delegation.server.jwt.HandlerRunner;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;
import org.oa4mp.delegation.server.request.ATRequest;
import org.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.server.server.*;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.server.api.storage.servlet.IssuerTransactionState;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.api.util.ClientDebugUtil;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.claims.IDTokenHandler;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.loader.oauth2.servlet.*;
import org.oa4mp.server.loader.oauth2.state.ScriptRuntimeEngineFactory;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenStore;
import org.oa4mp.server.loader.oauth2.storage.TokenInfoRecord;
import org.oa4mp.server.loader.oauth2.storage.TokenInfoRecordMap;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2TStoreInterface;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.loader.oauth2.tokens.UITokenUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.URI;
import java.util.*;

import static org.oa4mp.delegation.server.OA2Constants.NONCE;
import static org.oa4mp.delegation.server.OA2Constants.STATE;
import static org.oa4mp.delegation.server.server.RFC8693Constants.AUDIENCE;
import static org.oa4mp.delegation.server.server.RFC8693Constants.RESOURCE;
import static org.oa4mp.delegation.server.server.RFC8693Constants.*;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  2:03 PM
 */
public class OA2ATServlet extends AbstractAccessTokenServlet2 {

    @Override
    public void destroy() {
        super.destroy();
        shutdownCleanup(AbstractAccessTokenServlet2.txRecordCleanup); // try to shutdown cleanly
        for (Store s : getOA2SE().getAllStores()) {
            if (s instanceof SQLStore) {
                SQLStore sqlStore = (SQLStore) s;
                if (sqlStore.getConnectionPool() instanceof DerbyConnectionPool) {
                    sqlStore.getConnectionPool().shutdown();
                }
            }
        }
    }

    @Override
    public void preprocess(TransactionState state) throws Throwable {
        super.preprocess(state);
        /*
        As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

         The authorization server MUST include the HTTP "Cache-Control"
         response header field [RFC2616] with a value of "no-store" in any
         response containing tokens, credentials, or other sensitive
         information, as well as the "Pragma" response header field [RFC2616]
         with a value of "no-cache".
         */
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
            OA2ClientUtils.check(OA2ClientUtils.resolvePrototypes(getOA2SE(), (OA2Client) st.getClient()), givenRedirect);
            // Store the callback the user needs to use for this request, since the spec allows for many.

            // If there is a nonce in the initial request, it must be returned as part of the access token
            // response to prevent replay attacks.
            // Here is where we put the information from the session for generating claims in the id_token
            if (st.getNonce() != null && 0 < st.getNonce().length()) {
                p.put(NONCE, st.getNonce());
            }
        }

        p.put(OA2Constants.CLIENT_ID, st.getClient().getIdentifierString());
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
        // For CIL-771
        if (grantType.equals(OA2Constants.GRANT_TYPE_TOKEN_INFO)) {
            // Options are that the client is null (which means that this should be an admin client)
            // or that the client is not null, in which case we can only return information about the user
            // for this client.
            doTokenInfo(request, response);
            return true;
        }

        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();
        if (grantType.equals(RFC7523Constants.GRANT_TYPE_JWT_BEARER)) {
            // If the client is doing an RFC 7523 grant, then it must authorize accordingly
            // .
            BaseClient client = OA2HeaderUtils.getAndVerifyRFC7523Client(request, (OA2SE) getServiceEnvironment());
            if (client instanceof OA2Client) {
                OA2Client oa2Client = (OA2Client) client;
                // check client before continuing. Fail early, fail often!
                if (!oa2Client.isServiceClient()) {
                    throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "client not authorized to do RFC7523 requests");
                }
                checkAdminClientStatus(oa2Client.getIdentifier());
                doRFC7523(request, response, oa2Client);
            } else {
                doRFC7523InitiateFlow(request, response, client);
            }
            return true;
        }
        OA2Client client = getClient(request);
        // In all other cases, the client credentials must be sent.
        if (client == null) {
            warn("executeByGrant encountered a null client");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no such client");
        }
        checkAdminClientStatus(client.getIdentifier());

        MetaDebugUtil debugger = OA4MPServlet.createDebugger(client);
        debugger.trace(this, "starting execute by grant, grant = \"" + grantType + "\"");
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, client);
        if (!resolvedClient.isPublicClient()) {
            verifyClient(resolvedClient, request, true);
            //verifyClientSecret(resolvedClient, getClientSecret(request));
        }
        if (grantType.equals(GRANT_TYPE_CLIENT_CREDENTIALS)) {
            if (!oa2SE.isCCFEnabled()) {
                warn("Client " + client.getIdentifierString() + " requested a client credential flow but that is not enabled on this server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "client credentials flow not supported on this server ");
            }
            if (client.isPublicClient()) {
                warn("public client " + client.getIdentifierString() + " requested a client credential flow but is not allowed on this server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "client credential flow not supported for public clients");
            }
            if (!client.isServiceClient()) {
                warn("Client " + client.getIdentifierString() + " requested a client credential flow but is not allowed on this server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "client credential flow not supported for this client");
            }
            doRFC6749_4_4(request, response, resolvedClient);
            debugger.trace(this, "client credential flow completed, returning... ");
            return true;
        }
        if (grantType.equals(GRANT_TYPE_TOKEN_EXCHANGE)) {
            if (!oa2SE.isRfc8693Enabled()) {
                warn("Client " + client.getIdentifierString() + " requested a token exchange but token exchange is not enabled on this server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "token exchange not supported on this server ");
            }
            doRFC8693(resolvedClient, request, response);
            debugger.trace(this, "rfc8693 completed, returning... ");
            return true;
        }

        if (grantType.equals(RFC8628Constants.GRANT_TYPE_DEVICE_CODE)) {
            if (!oa2SE.isRfc8628Enabled()) {
                warn("Client " + client.getIdentifierString() + " requested a token exchange but token exchange is not enabled onthis server.");
                throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                        "device code flow not supported on this server ");
            }
            doRFC8628(resolvedClient, request, response);
            debugger.trace(this, "rfc8628 completed, returning... ");
            return true;
        }
        if (grantType.equals(OA2Constants.GRANT_TYPE_REFRESH_TOKEN)) {
            doRefresh(resolvedClient, request, response);
            return true;
        }
        if (grantType.equals(OA2Constants.GRANT_TYPE_AUTHORIZATION_CODE)) {
            // OAuth 2. spec., section 4.1.3 states that the grant type must be included and it must be code.
            IssuerTransactionState state = doAT(request, response, resolvedClient);
            writeATResponse(response, state);
            return true;
        }

        return false;
    }

    /**
     * Does <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.4"></a>client credential flow</a>
     *
     * @param request
     * @param response
     * @param client
     * @throws Throwable
     */
    protected void doRFC6749_4_4(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        ServletDebugUtil.printAllParameters(getClass(), request, true);
        String state = getFirstParameterValue(request, STATE);
        String nonce = getFirstParameterValue(request, NONCE);
        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) getOA2SE().getTransactionStore().create();
        String uri = serviceTransaction.getIdentifier().getUri().toString();
        if (-1 == uri.indexOf("/rfc6749_4_4")) {
            uri = uri.substring(0, uri.indexOf("/")) + "/rfc6749_4_4" + uri.substring(uri.indexOf("/"));
            uri = uri + "/" + (new Date()).getTime();
            serviceTransaction.setIdentifier(BasicIdentifier.newID(uri));
            serviceTransaction.setAuthorizationGrant(new AuthorizationGrantImpl(URI.create(uri)));
        }
        serviceTransaction.setRequestState(state);
        serviceTransaction.setNonce(nonce);
        serviceTransaction.setClient(client);
        serviceTransaction.setConsentPageOK(true);
        Date now = new Date();
        serviceTransaction.setAuthTime(now); // auth time is now.
        client.setLastAccessed(now);

        JSONObject claims = new JSONObject();
        List<String> audience = HeaderUtils.getParameters(request, AUDIENCE, " ");
        serviceTransaction.setAudience(audience);
        List<String> resource = HeaderUtils.getParameters(request, RESOURCE, " ");
        serviceTransaction.setResource(resource);
        if (null != request.getParameter(OA2Claims.ISSUER)) {
            List<String> issuers = HeaderUtils.getParameters(request, OA2Claims.ISSUER, null);
            // the contract is that the issuers must match the client id if present
            for (String issuer : issuers) {
                if (!client.getIdentifierString().equals(issuer)) {
                    throw new OA2ATException(OA2Errors.INVALID_SCOPE,
                            "unable to determine scopes",
                            HttpStatus.SC_BAD_REQUEST,
                            state, client);

                }
            }
        }
        serviceTransaction.setUserMetaData(claims); // set this so it exists for later.
        List<String> scopes = OA2HeaderUtils.getParameters(request, SCOPE, " ");
        // scopes are optional.
        if (!scopes.isEmpty()) {
            try {
                serviceTransaction.setScopes(ClientUtils.resolveScopes(
                        request,
                        serviceTransaction,
                        client,
                        scopes,
                        true, false, true));
            } catch (OA2RedirectableError redirectableError) {
                throw new OA2ATException(OA2Errors.INVALID_SCOPE,
                        "unable to determine scopes",
                        HttpStatus.SC_BAD_REQUEST,
                        state, client);
            }
        }
        String subject = getFirstParameterValue(request, SUBJECT);
        if (subject == null) {
            // Fix https://github.com/ncsa/oa4mp/issues/219
            // set default of the client ID and subject.
            serviceTransaction.setUsername(serviceTransaction.getClient().getIdentifierString());
            claims.put(OA2Claims.SUBJECT, serviceTransaction.getUsername());

        } else {
            serviceTransaction.setUsername(subject);
            claims.put(OA2Claims.SUBJECT, serviceTransaction.getUsername());
        }
        if (request.getParameter(OA2Constants.ACCESS_TOKEN_LIFETIME) != null) {
            String rawATLifetime = getFirstParameterValue(request, OA2Constants.ACCESS_TOKEN_LIFETIME);
            try {
                long at = XMLConfigUtil.getValueSecsOrMillis(rawATLifetime);
                serviceTransaction.setRequestedATLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set requested access token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        //   serviceTransaction.setAccessTokenLifetime(ClientUtils.computeATLifetime(serviceTransaction, client, getOA2SE()));

        if (request.getParameter(OA2Constants.REFRESH_LIFETIME) != null) {
            String rawATLifetime = getFirstParameterValue(request, OA2Constants.REFRESH_LIFETIME);
            try {
                long rt = XMLConfigUtil.getValueSecsOrMillis(rawATLifetime);
                serviceTransaction.setRequestedRTLifetime(rt);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set requested refresh token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
/*        if (client.isRTLifetimeEnabled()) {
            long lifetime = ClientUtils.computeRefreshLifetime(serviceTransaction, client, getOA2SE());
            serviceTransaction.setRefreshTokenLifetime(ClientUtils.computeRefreshLifetime(serviceTransaction, client, getOA2SE()));
            serviceTransaction.setRefreshTokenExpiresAt(System.currentTimeMillis() + lifetime);
        } else {
            serviceTransaction.setRefreshTokenLifetime(0L);
        }*/
        if (request.getParameter(OA2Constants.ID_TOKEN_LIFETIME) != null) {
            String rawATLifetime = getFirstParameterValue(request, OA2Constants.ID_TOKEN_LIFETIME);
            try {
                long idt = XMLConfigUtil.getValueSecsOrMillis(rawATLifetime);
                serviceTransaction.setRequestedIDTLifetime(idt);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set requested ID token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        //  serviceTransaction.setIDTokenLifetime(ClientUtils.computeIDTLifetime(serviceTransaction, client, getOA2SE()));


        OA2ServletUtils.processXAs(request, serviceTransaction, client);

        // ****** End of setup for request, setup for access token request
        processServiceClientRequest(request, response, client, serviceTransaction, true);

    }

    protected OA2Client getRFC7523Client(BaseClient baseClient, JSONObject jsonRequest) {
        if (baseClient instanceof OA2Client) {
            return (OA2Client) baseClient;
        }
        AdminClient adminClient = (AdminClient) baseClient;
        if (!adminClient.canInitializeFlows()) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "admin client not authorized to initiate flows."); // client does not exist.
        }
        Identifier clientID = BasicIdentifier.newID(jsonRequest.getString(OA2Claims.ISSUER));
        OA2Client client = (OA2Client) getOA2SE().getClientStore().get(clientID);
        if (client == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no such client: " + clientID); // client does not exist.
        }
        // have to check admin owns client
        List<Identifier> adminIDs = getOA2SE().getPermissionStore().getAdmins(clientID);
        if (adminIDs.isEmpty() || !adminIDs.contains(adminClient.getIdentifier())) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no such client: " + clientID); // client does not exist.
        }

        return client;
    }

    /**
     * Processes a request from a service client. This allows for getting tokens from a trusted
     * client directly from the token endpoint by sending in the authorization grant request
     * directly.
     *
     * @param request
     * @param response
     * @param adminBaseClient
     * @throws Throwable
     */
    protected void doRFC7523InitiateFlow(HttpServletRequest request, HttpServletResponse response, BaseClient adminBaseClient) throws Throwable {
        JSONObject tokenRequest = null;
        ServletDebugUtil.printAllParameters(getClass(), request, true);
        AdminClient adminClient = getOA2SE().getAdminClientStore().get(adminBaseClient.getIdentifier()); // get the full one
        if (adminClient == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no such admin client");
        }
        if (!adminClient.canInitializeFlows()) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "admin client not authorized to initiate flows.");
        }
        try {
            String tokenRequestRaw = request.getParameter(RFC7523Constants.ASSERTION);
            if (StringUtils.isTrivial(tokenRequestRaw)) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing json assertion");
            }
            // In our min-spec., this is unsigned since the admin does not necessarily have the client key(s)
            tokenRequest = MyOtherJWTUtil2.verifyAndReadJWT(tokenRequestRaw);


        } catch (IllegalArgumentException iax) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid JWT:" + iax.getMessage()); // Not a JWT

        } catch (Throwable t) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid json assertion:" + t.getMessage()); // Something is wrong with the JWT --
        }

        OA2Client client = getRFC7523Client(adminClient, tokenRequest);
        if (!getOA2SE().getPermissionStore().getAdmins(client.getIdentifier()).contains(adminClient.getIdentifier())) {
            debug("admin client \"" + adminClient.getIdentifierString() + "\" not authorized to use client \"" + client.getIdentifierString() + "\"");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "admin client not authorized to use this client ");
        }

        processRFC7523(request, response, tokenRequest, client);
    } // end RFC7523InitiateFlow

    private void processRFC7523(HttpServletRequest request, HttpServletResponse response, JSONObject tokenRequest, OA2Client client) throws Throwable {
        if (!tokenRequest.containsKey(OA2Claims.ISSUER)) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing issuer");
        }
        if (!client.getIdentifierString().equals(tokenRequest.getString(OA2Claims.ISSUER))) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid issuer");
        }

        if (tokenRequest.getLong(OA2Claims.EXPIRATION) * 1000L < System.currentTimeMillis()) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "expired assertion token");
        }
        Collection<String> scopes;
        if (tokenRequest.containsKey(OA2Constants.SCOPE)) {
            Object ss = tokenRequest.get(OA2Constants.SCOPE);
            if (ss instanceof JSONArray) {
                scopes = (JSONArray) ss;
            } else {
                scopes = new ArrayList<>();
                StringTokenizer stringTokenizer = new StringTokenizer(ss.toString(), " ");
                while (stringTokenizer.hasMoreTokens()) {
                    scopes.add(stringTokenizer.nextToken());
                }
            }
        } else {
            scopes = new ArrayList<>();
        }
        String state = tokenRequest.containsKey(STATE) ? tokenRequest.getString(STATE) : null;
        String nonce = tokenRequest.containsKey(NONCE) ? tokenRequest.getString(NONCE) : null;

        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) getOA2SE().getTransactionStore().create();

        URI newURI = Identifiers.uniqueIdentifier("oa4mp:/rfc7523", "transaction", Identifiers.VERSION_2_0_TAG, serviceTransaction.getAuthzGrantLifetime());
        // FIXME This should really come from the token forge, but that means making a few Issuer/response classes
        String sURI = newURI.toString();
        String[] ss = sURI.split("\\?");
        ss[0] = ss[0] + "/" + (new Date()).getTime();
        newURI = URI.create(ss[0]);
        serviceTransaction.setIdentifier(BasicIdentifier.newID(newURI));
        serviceTransaction.setAuthorizationGrant(new AuthorizationGrantImpl(newURI));
        serviceTransaction.setRequestState(state);
        serviceTransaction.setNonce(nonce);
        serviceTransaction.setClient(client);
        Date now = new Date();
        serviceTransaction.setAuthTime(now); // auth time is now.
        client.setLastAccessed(now);

        OA2ServletUtils.processXAs(tokenRequest, serviceTransaction, client);

        // Do claims
        JSONObject claims = new JSONObject();
        if (tokenRequest.containsKey(OA2Constants.ID_TOKEN)) {
            JSONObject idToken = tokenRequest.getJSONObject(OA2Constants.ID_TOKEN);
            claims.putAll(idToken);
            if (tokenRequest.containsKey(OA2Claims.SUBJECT)) {
                String user = tokenRequest.getString(OA2Claims.SUBJECT);
                claims.put(OA2Claims.SUBJECT, user);
                setUsername(serviceTransaction, client, user);

            } else {
                if (!idToken.containsKey(OA2Claims.SUBJECT)) {
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject");
                }
                setUsername(serviceTransaction, client, idToken.getString(OA2Claims.SUBJECT));
            }
        } else {
            if (!tokenRequest.containsKey(OA2Claims.SUBJECT)) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject");
            }
            String user = tokenRequest.getString(OA2Claims.SUBJECT);
            setUsername(serviceTransaction, client, user);
            claims.put(OA2Claims.SUBJECT, user);
        }
        serviceTransaction.setUserMetaData(claims); // set this so it exists for later.
        try {
            serviceTransaction.setScopes(ClientUtils.resolveScopes(request,
                    serviceTransaction,
                    client,
                    scopes,
                    true, false, false));
        } catch (OA2RedirectableError redirectableError) {
            throw new OA2ATException(OA2Errors.INVALID_SCOPE,
                    "unable to determine scopes",
                    HttpStatus.SC_BAD_REQUEST,
                    state, client);
        }
        if (tokenRequest.containsKey(OA2Constants.ACCESS_TOKEN_LIFETIME)) {
            String rawATLifetime = tokenRequest.getString(OA2Constants.ACCESS_TOKEN_LIFETIME);
            try {
                long at = XMLConfigUtil.getValueSecsOrMillis(rawATLifetime);
                //               long at = Long.parseLong(rawATLifetime);
                serviceTransaction.setRequestedATLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set requested access token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }

        //       serviceTransaction.setAccessTokenLifetime(ClientUtils.computeATLifetime(serviceTransaction, client, getOA2SE()));
        if (tokenRequest.containsKey(OA2Constants.REFRESH_LIFETIME)) {
            String rawRTLifetime = tokenRequest.getString(OA2Constants.REFRESH_LIFETIME);
            try {
                long at = XMLConfigUtil.getValueSecsOrMillis(rawRTLifetime);
                serviceTransaction.setRequestedRTLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set requested refresh token lifetime to \"" + rawRTLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }

        }

        if (tokenRequest.containsKey(OA2Constants.ID_TOKEN_LIFETIME)) {
            String rawLifetime = tokenRequest.getString(OA2Constants.ID_TOKEN_LIFETIME);
            try {
                long at = XMLConfigUtil.getValueSecsOrMillis(rawLifetime);
                serviceTransaction.setRequestedIDTLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set requested ID token lifetime to \"" + rawLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }
        try {
            String[] rawResource = extractArray(tokenRequest, RESOURCE);
            String[] rawAudience = extractArray(tokenRequest, AUDIENCE);
            OA2AuthorizedServletUtil.figureOutAudienceAndResource(serviceTransaction, rawResource, rawAudience);
        } catch (OA2GeneralError ge) {
            throw new OA2ATException(ge.getError(), ge.getDescription(), ge.getHttpStatus(), state, client);
        }
        serviceTransaction.setConsentPageOK(true);
        processServiceClientRequest(request, response, client, serviceTransaction, false);
    }

    /**
     * Processes a request from a service client. This allows for getting tokens from a trusted
     * client directly from the token endpoint by sending in the authorization grant request
     * directly.
     *
     * @param request
     * @param response
     * @param client
     * @throws Throwable
     */
    protected void doRFC7523(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        JSONObject tokenRequestRaw = null;
        try {
            String raw = request.getParameter(RFC7523Constants.ASSERTION);
            if (StringUtils.isTrivial(raw)) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing json assertion");
            }
            if (client.hasJWKS()) {
                tokenRequestRaw = MyOtherJWTUtil2.verifyAndReadJWT(raw, client.getJWKS());
            } else {
                if (client.hasJWKSURI()) {
                    tokenRequestRaw = MyOtherJWTUtil2.verifyAndReadJWT(raw, client.getJwksURI());
                } else {
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing JSON web key. Cannot verify signature."); // Not a JWT
                }
            }
        } catch (IllegalArgumentException iax) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid JWT:"); // Not a JWT

        } catch (Throwable t) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid json assertion:" + t.getMessage()); // Something is wrong with the JWT --
        }
        processRFC7523(request, response, tokenRequestRaw, client);
    } // end RFC7525

    /**
     * Checks if the user name is allowed for this client and if so sets it, if not an exception
     * is raised.
     *
     * @param serviceTransaction
     * @param client
     * @param user
     */
    protected void setUsername(OA2ServiceTransaction serviceTransaction, OA2Client client, String user) {
        if (client.getServiceClientUsers().contains("*")) {
            serviceTransaction.setUsername(user);
        } else {
            if (client.getServiceClientUsers().contains(user)) {
                serviceTransaction.setUsername(user);
            } else {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "user \"" + user + "\" does not have permission");
            }
        }

    }

    /**
     * Both RFC7523 and credential flow clients operate the same once the parameters have
     * been processed. This is code common to both for that.
     *
     * @param request
     * @param response
     * @param client
     * @param serviceTransaction
     * @throws Throwable
     */
    private void processServiceClientRequest(HttpServletRequest request,
                                             HttpServletResponse response,
                                             OA2Client client,
                                             OA2ServiceTransaction serviceTransaction,
                                             boolean isRFC6749_4_4) throws Throwable {
        serviceTransaction.setAccessTokenLifetime(ClientUtils.computeATLifetime(serviceTransaction, client, getOA2SE()));
        serviceTransaction.setIDTokenLifetime(ClientUtils.computeIDTLifetime(serviceTransaction, client, getOA2SE()));
        if (client.isRTLifetimeEnabled()) {
            long lifetime = ClientUtils.computeRefreshLifetime(serviceTransaction, client, getOA2SE());
            serviceTransaction.setRefreshTokenLifetime(ClientUtils.computeRefreshLifetime(serviceTransaction, client, getOA2SE()));
            serviceTransaction.setRefreshTokenExpiresAt(System.currentTimeMillis() + lifetime);
        } else {
            serviceTransaction.setRefreshTokenLifetime(0L);
        }
        ATRequest atRequest = getATRequest(request, serviceTransaction, client);
        ATIResponse2 atiResponse2 = (ATIResponse2) getATI().process(atRequest);
        serviceTransaction.setAccessToken(atiResponse2.getAccessToken());
        serviceTransaction.setAccessTokenValid(true);
        if (client.isRTLifetimeEnabled()) {
            serviceTransaction.setRefreshToken(atiResponse2.getRefreshToken());
            serviceTransaction.setRefreshTokenValid(true);
        } else {
            serviceTransaction.setRefreshTokenValid(false);
        }

        getOA2SE().getTransactionStore().save(serviceTransaction);
        XMLMap backup = new XMLMap();
        getOA2SE().getTransactionStore().getMapConverter().toMap(serviceTransaction, backup);
        // Almost ready to rock and roll. Need the issuer transaction state, then do a standard AT
        // This, among other things, runs QDL scripts.
        IssuerTransactionState issuerTransactionState = new IssuerTransactionState(request, response, new HashMap<>(),
                serviceTransaction, backup, atiResponse2);
        // Do the auth claims.
        HandlerRunner handlerRunner = new HandlerRunner(serviceTransaction, ScriptRuntimeEngineFactory.createRTE(getOA2SE(), serviceTransaction, client.getConfig()));
        OA2ClientUtils.setupHandlers(handlerRunner, getOA2SE(), serviceTransaction, client, null, null, null, request);
        try {
            handlerRunner.doAuthClaims();
        } catch (Throwable throwable) {
            // NOTE at this point there is no "backup" possible if there is an error since this is starting the flow.
            // Sending a null cues in the handler not to rollback.
            OA2ServletUtils.handleScriptEngineException(this, getOA2SE(), throwable, createDebugger(serviceTransaction.getClient()), serviceTransaction, null);
        }
        issuerTransactionState = doAT(issuerTransactionState, client);
        // Now, get the right signing key
        VirtualIssuer vo = getOA2SE().getVI(client.getIdentifier());
        JSONWebKey key = null;
        if (vo != null && vo.getJsonWebKeys() != null) {
            key = vo.getJsonWebKeys().get(vo.getDefaultKeyID());
        } else {
            key = getOA2SE().getJsonWebKeys().getDefault();
        }
        ATIResponse2 atResponse = (ATIResponse2) issuerTransactionState.getIssuerResponse();
        atResponse.setJsonWebKey(key);
        if (isRFC6749_4_4) {
            // Only return a refresh token if they explicitly request it with the offline_access
            // scope AND they are allowed to get
            if (!serviceTransaction.getScopes().contains(OA2Scopes.SCOPE_OFFLINE_ACCESS)) {
                ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setRefreshToken(null);
            }
            if (!serviceTransaction.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setIdToken(null);
            }
        }
        writeATResponse(response, issuerTransactionState);
    }

    private static String[] extractArray(JSONObject jsonRequest, String key) {
        String[] raw;
        if (jsonRequest.containsKey(key)) {
            Object obj = jsonRequest.get(key); // Either a single element or JSON array
            if (obj instanceof JSONArray) {
                JSONArray array = (JSONArray) obj;
                raw = new String[array.size()];
                for (int i = 0; i < array.size(); i++) {
                    raw[i] = array.getString(i);
                }
            } else {
                raw = new String[]{(String) obj};
            }
        } else {
            raw = new String[]{};
        }
        return raw;
    }

    /**
     * Contract is that the request contains a valid access token. Look up the transaction
     * then search for the user's other transactions by username.
     *
     * @param request
     * @param response
     */
    private void doTokenInfo(HttpServletRequest request, HttpServletResponse response) throws IOException {
        /*
        Most of the machinery here is figuring out what type of token (JWT, default), looking up
        the transaction which may be in a TX record and finally verifying the token if sent.
         */
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();

        AdminClient adminClient = null;
        OA2Client oa2Client = null;
        boolean isAdminClient = false;
        try {
            adminClient = getAdminClient(request);
            if (!adminClient.isListUsers()) {
                throw new IllegalArgumentException("The given admin client does not have listing permissions");
            }
            isAdminClient = true; // if we get here, we have one.
        } catch (UnknownClientException unknownClientException) {
            oa2Client = (OA2Client) getClient(request);
        }
        // So the test is this: One of the above gets for a client has to work. If getClient fails
        // it will be because of an unknown client exception. At this point, one of the two clients
        //exists
        // Check the token
        AccessTokenImpl at = null;
        RefreshTokenImpl rt = null;
        OA2ServiceTransaction t = null;
        boolean sentAT = false;
        if (request.getParameterMap().containsKey(OA2Constants.ACCESS_TOKEN)) {
            String rawAT = request.getParameter(OA2Constants.ACCESS_TOKEN);
            if (StringUtils.isTrivial(rawAT)) {
                throw new IllegalArgumentException("missing " + OA2Constants.ACCESS_TOKEN);
            }
            at = UITokenUtils.getAT(rawAT);// gets the token, but no verification
            if (at.isExpired()) {
                throw new IllegalArgumentException("access token is expired");
            }
            t = (OA2ServiceTransaction) getOA2SE().getTransactionStore().get(at);
            if (t == null) {
                t = OA2TokenUtils.getTransactionFromTX(oa2SE, at, null);
            }
            sentAT = true;
        }
        if (request.getParameterMap().containsKey(OA2Constants.REFRESH_TOKEN)) {
            String rawRT = request.getParameter(OA2Constants.REFRESH_TOKEN);
            if (StringUtils.isTrivial(rawRT)) {
                throw new IllegalArgumentException("missing " + OA2Constants.REFRESH_TOKEN);
            }
            rt = UITokenUtils.getRT(rawRT);
            if (rt.isExpired()) {
                throw new IllegalArgumentException("refresh token is expired");
            }
            t = ((OA2TStoreInterface) getOA2SE().getTransactionStore()).get(rt);
            if (t == null) {
                t = OA2TokenUtils.getTransactionFromTX(oa2SE, rt, null);
            }
        }

        // So if after figuring out the token type and snooping through TX records we can't get a transaction
        // one does not actually exist.
        if (t == null) throw new IllegalArgumentException("transaction not found");

        if (sentAT) {
            if (!t.isAccessTokenValid()) throw new IllegalArgumentException("invalid access token");
        } else {
            if (!t.isRefreshTokenValid()) throw new IllegalArgumentException("invalid refresh token");
        }

        Identifier clientID = t.getClient().getIdentifier();
        // At this point we need to check signatures which involve

        // FINALLY, we have the client so we can unscramble the signatures and make sure that
        // they work.
        TokenImpl token = at == null ? rt : at;
        if (isAdminClient) {
            if (token.isJWT()) {
                JSONWebKeys jsonWebKeys;
                if (adminClient.getVirtualIssuer() == null) {
                    jsonWebKeys = oa2SE.getJsonWebKeys();
                } else {
                    VirtualIssuer vo = (VirtualIssuer) oa2SE.getVIStore().get(adminClient.getVirtualIssuer());
                    if (vo == null) {
                        // Admin client is in a VO but no such VO is found. This implies an internal error
                        throw new NFWException("Virtual issuer \"" + adminClient.getVirtualIssuer() + "\"not found.");
                    }
                    jsonWebKeys = vo.getJsonWebKeys();
                }
                JWTUtil.verifyAndReadJWT(token.getToken(), jsonWebKeys); // might throw an exception
            }
        } else {
            if (at.isJWT()) {
                JSONWebKeys jsonWebKeys;
                VirtualIssuer vo = getOA2SE().getVI(clientID);
                if (vo == null) {
                    jsonWebKeys = oa2SE.getJsonWebKeys();
                } else {
                    jsonWebKeys = vo.getJsonWebKeys();
                }
                JWTUtil.verifyAndReadJWT(at.getToken(), jsonWebKeys); // might throw an exception
            }
        }


        if (isAdminClient) {
            List<Identifier> admins = oa2SE.getPermissionStore().getAdmins(clientID);
             /* The admin client, even if it can list other users, cannot just send along an
                access token from any place. There must be a relationship of the token to at
                least one of the clients managed by this.
              */
            if (!admins.contains(adminClient.getIdentifier())) {
                throw new IllegalArgumentException("client is not associated with this admin.");
            }

        } else {
            if (!clientID.equals(oa2Client.getIdentifier())) {
                throw new IllegalArgumentException("client is not associated with this access token.");
            }
        }
        OA2TStoreInterface tStore = (OA2TStoreInterface) getOA2SE().getTransactionStore();
        // This is everything the system knows about tokens for this user. Now we need to filter
        TokenInfoRecordMap tirs = tStore.getTokenInfo(t.getUsername());
        // Now we have to pull out every token record and add them.

        Set<Identifier> keys = null;
        // Figure out the set of client IDs that can be returned.
        if (isAdminClient) {
            if (adminClient.isListUsersInOtherClients()) {
            } else {
                keys = new HashSet<>(oa2SE.getPermissionStore().getClients(adminClient.getIdentifier())); // has to be a set
            }
        } else {
            keys = new HashSet();
            keys.add(clientID);
        }
        tirs.reduceTo(keys);

        for (Identifier tID : tirs.getTransactionIDs()) {
            Identifier tempCID = tirs.getClientID(tID);
            for (Object txRecord : oa2SE.getTxStore().getByParentID(tID)) {
                TokenInfoRecord tir = new TokenInfoRecord();
                tir.fromTXRecord(tempCID, (TXRecord) txRecord);
                tirs.put(tir);
            }
        }


        JSONObject json = new JSONObject(); //top level object
        json.put("user_uid", t.getUsername());
        JSONArray clientArray = new JSONArray();
        /*
        Response is a JSON object of the form
        {"user_id":uid,
          "clients":[
             {clientid:[{tid:[list of tokens]}, {tid:[list of tokens]}}*]
            ]
          }
         */
        for (Identifier cid : tirs.getClientIDs()) {
            Map<Identifier, List<TokenInfoRecord>> records = tirs.sortByClientID(cid);
            JSONObject currentTrans = new JSONObject();
            JSONArray allTokenArray = new JSONArray();

            for (Identifier transactionID : records.keySet()) {
                List<TokenInfoRecord> list = records.get(transactionID);
                JSONArray a = new JSONArray();
                for (TokenInfoRecord tokenInfoRecord : list) {
                    a.add(tokenInfoRecord.toJSON());
                }
                currentTrans.put(OA2Constants.AUTHORIZATION_CODE, transactionID.toString());
                currentTrans.put("tokens", a);
                allTokenArray.add(currentTrans);
            }

            JSONObject x = new JSONObject();
            x.put(OA2Constants.CLIENT_ID, cid.toString());
            x.put("transactions", allTokenArray);
            clientArray.add(x);
        }

        json.put("clients", clientArray);
        // Look up by client id and username(s).
        // This means searching for transactions and snooping through TX records too. Only return valid
        // tokens.
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        Writer osw = response.getWriter();
        json.write(osw);
        osw.flush();
        osw.close();
    }

    private JSONObject formatTokenInfoEntry(Identifier clientID, List<TokenInfoRecord> records) {
        JSONObject jsonObject = new JSONObject();
        JSONArray array = new JSONArray();
        for (TokenInfoRecord tir : records) {
            array.add(tir.toJSON());
        }
        jsonObject.put(clientID.toString(), array);
        return jsonObject;
    }

    private void writeATResponse(HttpServletResponse response, IssuerTransactionState state) throws IOException {
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
        atResponse.setUserMetadata(t.getUserMetaData());
        atResponse.write(response);
    }

    private RFC8693Thingie startRFC8693(OA2Client client,
                                        HttpServletRequest request,
                                        HttpServletResponse response) throws IOException {

        RFC8693Thingie rfc8693Thingie = new RFC8693Thingie();
        String subjectToken = getFirstParameterValue(request, SUBJECT_TOKEN);
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(client);
        debugger.trace(this, "Starting RFC 8693 token exchange");
        printAllParameters(request, debugger);
/*
        if (debugger.isEnabled()) {
            ServletDebugUtil.printAllParameters(this.getClass(), request, true);
        }
*/
        if (subjectToken == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject token");
        }
        String requestedTokenType = getFirstParameterValue(request, REQUESTED_TOKEN_TYPE);

        if (StringUtils.isTrivial(requestedTokenType)) {
            requestedTokenType = ACCESS_TOKEN_TYPE;
        }
        debugger.trace(this, "requested token type set to " + requestedTokenType);
        // And now do the spec stuff for the actor token
        String actorToken = getFirstParameterValue(request, ACTOR_TOKEN);
        String actorTokenType = getFirstParameterValue(request, ACTOR_TOKEN_TYPE);
        // We don't support the actor token, and the spec says that we can ignore it
        // *but* if it is missing and the actor token type is there, reject the request
        if ((actorToken == null && actorTokenType != null)) {
            debugger.trace(this, "actor token not allowed");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    "actor token type is not allowed");
        }
        AccessTokenImpl accessToken = null;
        RefreshTokenImpl refreshToken = null;
        OA2ServiceTransaction t = null;
        OA2SE oa2se = (OA2SE) OA4MPServlet.getServiceEnvironment();
        String subjectTokenType = getFirstParameterValue(request, SUBJECT_TOKEN_TYPE);
        if (subjectTokenType == null) {
            debugger.trace(this, "missing subject token type");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject token type");
        }

        /*
        These can come as multiple space delimited string and as multiple parameters, so it is possible to get
        arrays of arrays of these and they have to be regularized to a single list for processing.
        NOTE: These are ignored for regular access tokens. For SciTokens we *should* allow exchanging
        a token for a weaker one. Need to figure out what weaker means though.
         */
        rfc8693Thingie.scopes = convertToList(request, OA2Constants.SCOPE);
        /*
          There is an entire RFC now associated with the resource parameter:

          https://tools.ietf.org/html/rfc8707

          Argh!
         */
        rfc8693Thingie.audience = convertToList(request, AUDIENCE);
        rfc8693Thingie.resources = convertToList(request, RESOURCE);

        //CIL-974
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2se, client);
        debugger.trace(this, "got web keys, getting transaction from the client id in the request");
        IDTokenImpl idToken = null;
        switch (subjectTokenType) {
            case ACCESS_TOKEN_TYPE:
                accessToken = OA2TokenUtils.getAT(subjectToken, oa2se, keys, debugger);
                t = ((OA2TStoreInterface) getTransactionStore()).get(accessToken, client.getIdentifier());
                break;
            case REFRESH_TOKEN_TYPE:
                refreshToken = OA2TokenUtils.getRT(subjectToken, oa2se, keys, debugger);
                RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
                t = (OA2ServiceTransaction) rts.get(refreshToken, client.getIdentifier());
                break;
            case ID_TOKEN_TYPE:
                idToken = OA2TokenUtils.getIDToken(subjectToken, oa2se, keys, debugger);
                t = ((OA2TStoreInterface) getTransactionStore()).getByIDTokenID(BasicIdentifier.newID(idToken.getJti()));
                break;
            default:
                throw new NFWException("unknown subject type \"" + subjectTokenType + "\"");
        }
        /*
         New 𝕰𝖗s𝖆𝖙𝖟 clients: It is possible that if there is no transaction at this point, a substitution
         is starting. In that case we have to see if there is a transaction at all with this
         token, then check if the original client on the token delegates to the given requesting
         client.
         If so, clone the transaction, change the temp_token (which MUST be unique since it is the primary key)
         update the client and save it. Continue as if this were a regular request.
         */
        /*
        Topography of the store. Auth grants (called temp_token for historical reasons) are
        unique identifiers. If there are for a flow with AG == A, then the new flow a
        completely new AG. Access tokens and refresh tokens, however, are NOT unique in the database
         */
        boolean isInitialErsatzExchange = false; // set true ONLY if this is an initial swap of a provisioner to ersats client.
        if (t == null) {
            debugger.trace(this, "transaction not found from credentials for client \""
                    + client.getIdentifierString() + "\", attempting to get transaction from the token itself");

            switch (subjectTokenType) {
                case ACCESS_TOKEN_TYPE:
                    t = (OA2ServiceTransaction) getTransactionStore().get(accessToken);
                    break;
                case REFRESH_TOKEN_TYPE:
                    RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
                    try {
                        t = rts.get(refreshToken);
                    } catch (TransactionNotFoundException transactionNotFoundException) {
                        // fine. Look in the TX store later.
                    }
                    break;
            }
            // Fix for https://github.com/ncsa/oa4mp/issues/211
            // Needed to check exchange store in case multiple refreshes done at some point.
            if (t == null) {
                // if there is no such transaction found, then this is probably from a previous exchange. Go find it
                try {
                    if (accessToken != null) {
                        t = OA2TokenUtils.getTransactionFromTX(oa2se, accessToken, debugger);
                    }
                    if (refreshToken != null) {
                        t = OA2TokenUtils.getTransactionFromTX(oa2se, refreshToken, debugger);
                        if (t != null) {
                            rfc8693Thingie.oldRTTX = (TXRecord) oa2se.getTxStore().get(refreshToken.getJTIAsIdentifier());
                        }
                    }
                    if (idToken != null) {
                        t = OA2TokenUtils.getTransactionFromTX(oa2se, idToken, debugger);
                    }
                    if (t != null) {
                        debugger.trace("found transaction from TX record.");
                    }

                } catch (OA2GeneralError oa2GeneralError) {
                    if (!(debugger instanceof ClientDebugUtil)) {
                        // last ditch effort to tell us what client is doing this.
                        info("Could not find transaction for client " + client.getIdentifierString());
                    }
                    throw oa2GeneralError;
                }
            }

            if (t == null) {
                // Still null. Ain't one no place. Bail.
                info("No pending transactions found anywhere for client \"" + client.getIdentifierString() + "\".");
                throw new OA2ATException(OA2Errors.INVALID_GRANT, "no pending transaction found.", client);
            }
            if (!client.getIdentifierString().equals(t.getClient().getIdentifierString())) {

                debugger.trace(this, "transaction found, checking for ersatz client:" + t.summary());

                // found something under another client id. Check for substitution
                PermissionsStore<? extends Permission> pStore = getOA2SE().getPermissionStore();
                List<Identifier> eAdminIDS = pStore.getAdmins(client.getIdentifier());
                Permission ersatzChain = null;
                Identifier pAdminID = null;
                List<Identifier> pAdminIDS = pStore.getAdmins(t.getOA2Client().getIdentifier());
                if (eAdminIDS.isEmpty()) {
                    if (!pAdminIDS.isEmpty()) {
                        debugger.trace(this, "ersatz client is not managed, any place");
                        throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                                "no substitutions allowed for unmanaged clients",
                                HttpStatus.SC_UNAUTHORIZED, null, t.getClient());
                    }
                }
                if (1 == eAdminIDS.size()) {
                    if (!pAdminIDS.contains(eAdminIDS.get(0))) { // we only care that the admin for the E client is also one for the P client
                        throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                                "clients must be managed by same admin",
                                HttpStatus.SC_UNAUTHORIZED, null, t.getClient());
                    }
                    pAdminID = pAdminIDS.get(0);
                }
                ersatzChain = pStore.getErsatzChain(pAdminID, t.getOA2Client().getIdentifier(), client.getIdentifier());
                if (1 < eAdminIDS.size()) {
                    // So if there is a client managed by multiple admins, we don't just switch
                    // virtual organizations in the middle. No hijacking allowed. This is possible to do, but generally
                    // admins do not share clients, so we'll flag it as an exception here and if this
                    // ever needs to change, this tells us it is not working.
                    debugger.trace(this, "multiple admins for client " + client.getIdentifierString());
                    throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                            "multiple administrators for a managed client is not allowed",
                            HttpStatus.SC_UNAUTHORIZED, null, t.getClient());
                }

                if (ersatzChain == null) {
                    // This client cannot sub in the original flow.
                    debugger.trace(this, "client \"" + client.getIdentifier() + "\" does not have permission to sub for \"" + t.getOA2Client().getIdentifier() + "\".");
                    throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                            "client does not have permission to substitute, access denied",
                            HttpStatus.SC_UNAUTHORIZED, null, t.getClient());

                }
                // now we can clone the transaction
                ColumnMap map = new ColumnMap();
                getTransactionStore().getXMLConverter().toMap(t, map);
                debugger.trace(this, "cloning transaction, setting up new flow");

                OA2ServiceTransaction t2 = (OA2ServiceTransaction) getTransactionStore().getXMLConverter().fromMap(map, null);
                // now create a new AG
                AuthorizationGrantImpl ag = (AuthorizationGrantImpl) getTF2().getAuthorizationGrant(); // new grant
                AccessTokenImpl at = getTF2().getAccessToken();
                RefreshTokenImpl rt = getTF2().getRefreshToken();
                t2.setIdentifier(BasicIdentifier.newID(ag.getJti()));
                t2.setAuthorizationGrant(ag); // This is used as the !key in the store.
                t2.setAccessToken(at);
                t2.setRefreshToken(rt);
                // Need inheritance from provisioning client,
                try {
                    client = createErsatz(t.getOA2Client().getIdentifier(), client, ersatzChain.getErsatzChain());
                } catch (UnknownClientException ucx) {
                    debugger.trace(this, "ersatz client has unknown provisioner in chain.");

                    throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                            ucx.getMessage(), HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            t.getRequestState(),
                            t.getClient());
                }
                t2.setProvisioningClientID(t.getOA2Client().getIdentifier()); // So we can find it later
                t2.setProvisioningAdminID(pAdminID);
                t2.setClient(client);
                t2.getUserMetaData().put(OA2Claims.AUDIENCE, client.getIdentifierString()); // so id token has right audience
                if (client.isRTLifetimeEnabled()) {
                    long lifetime = ClientUtils.computeRefreshLifetime(t2, client, getOA2SE());
                    t2.setRefreshTokenLifetime(lifetime);
                    t2.setRefreshTokenExpiresAt(System.currentTimeMillis() + lifetime);
                } else {
                    t2.setRefreshTokenLifetime(0L);
                }
                JSONObject atData = t2.getATData();
                if (atData.containsKey("client_id")) {
                    atData.put("client_id", client.getIdentifierString());
                }
                t2.setATData(atData);
                t2.setAccessTokenLifetime(ClientUtils.computeATLifetime(t2, client, getOA2SE()));
                t2.setIDTokenLifetime(ClientUtils.computeIDTLifetime(t2, client, getOA2SE()));

                if (!client.isErsatzInheritIDToken()) {
                    t2.setUserMetaData(new JSONObject());//
                    // Always update the id
                    t2.getUserMetaData().put(JWT_ID, ((OA2TokenForge) getOA2SE().getTokenForge()).getIDToken().getJti().toString());
                    if (client.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                        // or it will bomb in the check that this is an OIDC client.
                        t2.getUserMetaData().put(OA2Claims.SUBJECT, client.getIdentifierString());
                    }
                    // Inherit the issuer no matter what, or the ID token will be invalid.
                    // Figuring out the issuer in the first place was hard, but if they insist, they can
                    // reset it later.
                    t2.getUserMetaData().put(ISSUER, t.getUserMetaData().getString(ISSUER));
                }
                debugger = OA4MPServlet.createDebugger(client); // switch over to logging for the 𝕰𝖗s𝖆𝖙𝖟 client.
                getTransactionStore().save(t2);
                // rock on. A new transaction has been created for this and the flow from the original may now diverge.
                t = t2;
                rfc8693Thingie.isErsatz = true;
            }
        }


        rfc8693Thingie.transaction = t;
        if (client.isErsatzClient() && !client.isReadOnly()) {
            // Gotten this far and there is an ersatz client. Read only is a good as "has been resolved"
            debugger.trace(this, "resolving ersatz client");
            try {
                Permission p = getOA2SE().getPermissionStore().getErsatzChain(t.getProvisioningAdminID(), t.getProvisioningClientID(), client.getIdentifier());
                if (p == null) {
                    throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                            "permissions not found for admin '" + t.getProvisioningAdminID() +
                                    "' + and provisioner '" + t.getProvisioningClientID() + "'", HttpStatus.SC_UNAUTHORIZED,
                            t.getRequestState(),
                            client);
                }
                client = createErsatz(t.getProvisioningClientID(), client, p.getErsatzChain());
                debugger = OA4MPServlet.createDebugger(client);
                t.setClient(client);
            } catch (UnknownClientException ucx) {
                debugger.trace(this, "No ersatz client found");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        ucx.getMessage(), HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        t.getRequestState(),
                        t.getClient());
            }
        }

        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(t);
            debugger.trace(this, "setting transaction for debugger to " + t.summary());
        }
        // Finally can check access here. Access for exchange is same as for refresh token.
        if (!t.getFlowStates().acceptRequests || !t.getFlowStates().refreshToken) {
            debugger.trace(this, "Flow denied");
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "token exchange access denied",
                    t.getRequestState(),
                    t.getClient());
        }

        rfc8693Thingie.debugger = debugger;
        rfc8693Thingie.client = client;
        rfc8693Thingie.requestTokenType = requestedTokenType;
        if (!client.isRTLifetimeEnabled() && rfc8693Thingie.requestTokenType.equals(REFRESH_TOKEN_TYPE)) {
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "refresh tokens disabled for this client",
                    t.getRequestState(),
                    t.getClient());
        }


        return rfc8693Thingie;
    }

    /**
     * A class that encapsulates the results of setting up RFC 8693. This code is large
     * and messy so should be in a single place.
     */
    public static class RFC8693Thingie {
        public boolean isErsatz = false;
        public OA2ServiceTransaction transaction;
        public MetaDebugUtil debugger;
        public OA2Client client;
        public String requestTokenType;
        public List<String> scopes;
        /*
           There is an entire RFC now associated with the resource parameter:

           https://tools.ietf.org/html/rfc8707

           Argh!
          */
        public List<String> audience;
        public List<String> resources;
        /**
         * If this is not a fork and there was a previous TX record, return it here so
         * it can have its grace period set later. If this is null, there is no previous TX record.
         */
        public TXRecord oldRTTX = null;

    }

    private void doRFC8693Fork(RFC8693Thingie rfc8693Thingie,
                               HttpServletRequest request,
                               HttpServletResponse response) throws IOException {
        OA2ServiceTransaction t = rfc8693Thingie.transaction;
        OA2Client client = rfc8693Thingie.client;
        MetaDebugUtil debugger = rfc8693Thingie.debugger;
        String requestedTokenType = rfc8693Thingie.requestTokenType;
        List<String> scopes = rfc8693Thingie.scopes;
        List<String> audience = rfc8693Thingie.audience;
        List<String> resources = rfc8693Thingie.resources;
        OA2SE oa2se = getOA2SE();
        boolean returnRTOnly = rfc8693Thingie.requestTokenType.equals(REFRESH_TOKEN_TYPE);
        /*
             Earth shaking change is that we need to create a new token exchange record for each exchange since the tokens
             have a lifetime and lifecycle of their own. Once in the wild, people may come back to this
             service and swap them willy nilly.
           */
        XMLMap tBackup = GenericStoreUtils.toXML(getTransactionStore(), t);
        OA2ServletUtils.processXAs(request, t, client);
/*
        if (client.hasExtendedAttributeSupport()) {
            ExtendedParameters xp = new ExtendedParameters();
            // Take the parameters and parse them into configuration objects,
            JSONObject extAttr = xp.snoopParameters(request.getParameterMap());
            if (extAttr != null && !extAttr.isEmpty()) {
                t.setExtendedAttributes(extAttr);
            }
        }
*/
        TXRecord newIDTX = null;
        TXRecord newATTX = null;
        TXRecord newRTTX = null;
        if (!returnRTOnly) {

            // ID token setup
            newIDTX = (TXRecord) oa2se.getTxStore().create();
            newIDTX.setIdentifier(((OA2TokenForge) oa2se.getTokenForge()).getIDTokenProvider().get());
            newIDTX.setTokenType(ID_TOKEN_TYPE);
            newIDTX.setParentID(t.getIdentifier());
            newIDTX.setIssuedAt(System.currentTimeMillis());
            // access token setup
            newATTX = (TXRecord) oa2se.getTxStore().create();
            newATTX.setTokenType(ACCESS_TOKEN_TYPE);
            newATTX.setParentID(t.getIdentifier());
            if (!audience.isEmpty()) {
                newATTX.setAudience(audience);
            }
            if (!scopes.isEmpty()) {
                debugger.trace(this, "user requested scopes:" + scopes);
                newATTX.setScopes(scopes);
            } else {
                // If no scopes sent with request, revert to scopes in original request.
                debugger.trace(this, "NO user requested scopes");
                //   newTXR.setScopes(t.getScopes());
            }
            if (!resources.isEmpty()) {
                // convert to URIs
                ArrayList<URI> r = new ArrayList<>();
                for (String x : resources) {
                    try {
                        r.add(URI.create(x));
                    } catch (Throwable throwable) {
                        debugger.info(this, "rejected resource request \"" + x + "\"");
                        info("rejected resource request \"" + x + "\"");
                    }
                }
                newATTX.setResource(r);
            }
            newATTX.setIssuedAt(System.currentTimeMillis());
        }

        // refresh token setup
        newRTTX = (TXRecord) oa2se.getTxStore().create();
        newRTTX.setTokenType(REFRESH_TOKEN_TYPE);
        newRTTX.setParentID(t.getIdentifier());
        newRTTX.setIssuedAt(System.currentTimeMillis());

        RTIRequest rtiRequest = new RTIRequest(request, t, t.getAccessToken(), oa2se.isOIDCEnabled());
        RTI2 rtIssuer = new RTI2(getTF2(), OA4MPServlet.getServiceEnvironment().getServiceAddress());
        RTIResponse rtiResponse = (RTIResponse) rtIssuer.process(rtiRequest);
        debugger.trace(this, "rti response=" + rtiResponse);
        rtiResponse.setSignToken(client.isSignTokens());
        // These are the claims that are returned in the RFC's required response. They have nothing to do
        // with id token claims, fyi.
        JSONObject rfcClaims = new JSONObject();

        debugger.trace(this, "requested token type = " + requestedTokenType);
        // Implicitly again, forking the flow effectively means the token type is access and the client id is different
        TXRecord activeTX = newATTX;
        // The requested token type for the fork is an access token.
        if (returnRTOnly) {
            rfcClaims.put(ISSUED_TOKEN_TYPE, REFRESH_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
            rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_N_A);
        } else {
            rfcClaims.put(ISSUED_TOKEN_TYPE, ACCESS_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
            rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_BEARER); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
        }
        if (!returnRTOnly) {
            // set up the access token TX
            newATTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getAccessToken().getToken()));
            newATTX.setExpiresAt(newATTX.getIssuedAt() + newATTX.getLifetime());
            // Set up the ID token TX
            newIDTX.setExpiresAt(newIDTX.getIssuedAt() + newIDTX.getLifetime());

        }
        // set up the refresh token TX

        newRTTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getRefreshToken().getToken()));
        newRTTX = (TXRecord) oa2se.getTxStore().create();
        newRTTX.setTokenType(REFRESH_TOKEN_TYPE);
        newRTTX.setExpiresAt(newRTTX.getIssuedAt() + newRTTX.getLifetime());
        newRTTX.setParentID(t.getIdentifier());
        newRTTX.setIssuedAt(System.currentTimeMillis());
        newRTTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getRefreshToken().getJti()));
        newRTTX.setExpiresAt(newRTTX.getIssuedAt() + newRTTX.getLifetime());

        t.setRefreshToken(rtiResponse.getRefreshToken()); // make sure it is not the ersatz client refresh token.
        if (rtiResponse.getRefreshToken().isJWT()) {
            rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().getToken());
            newRTTX.setStoredToken(rtiResponse.getRefreshToken().getToken());
        } else {
            rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().encodeToken());
        }
        getOA2SE().getTxStore().save(newRTTX);


        HandlerRunner handlerRunner = new HandlerRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2se, t, activeTX, client.getConfig()));
        try {
            OA2ClientUtils.setupHandlers(handlerRunner, oa2se, t, client, newIDTX, newATTX, newRTTX, request);
            // NOTE WELL that the next two lines are where our identifiers are used to create JWTs (like SciTokens)
            // so if this is not done, the wrong token type will be returned.
            handlerRunner.doTokenExchange();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2se, throwable, debugger, t, tBackup, activeTX);
        }

        setupTokenResponseFromRunner(client, rtiResponse, oa2se, t, handlerRunner, true, debugger);
        debugger.trace(this, "rtiResponse after token setup:" + rtiResponse);

        if (!returnRTOnly) {
            newIDTX.setValid(true);
            oa2se.getTxStore().save(newIDTX);
        }
        //    t.setUserMetaData(rtiResponse.getIdToken().getPayload());

        if (!returnRTOnly) {
            if (!((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
                // native OA4MP token, set accounting info here.
                AccessTokenImpl at = (AccessTokenImpl) rtiResponse.getAccessToken();
                newATTX.setIssuedAt(at.getIssuedAt());
                newATTX.setLifetime(at.getLifetime());
                newATTX.setExpiresAt(at.getExpiresAt());
            }
            newATTX.setValid(true);
            oa2se.getTxStore().save(newATTX);

        }
        //      t.setATData(((AccessTokenImpl) rtiRequest.getAccessToken()).getPayload());
        if (rtiResponse.hasRefreshToken() && !rtiResponse.getRefreshToken().isJWT()) {
            // native OA4MP token, set accounting info here.
            RefreshTokenImpl rt = rtiResponse.getRefreshToken();
            newRTTX.setIssuedAt(rt.getIssuedAt());
            newRTTX.setLifetime(rt.getLifetime());
            newRTTX.setExpiresAt(rt.getExpiresAt());
        }
        newRTTX.setValid(true);
        oa2se.getTxStore().save(newRTTX);
        //  t.setRTData(jwtRunner.getRefreshTokenHandler().getPayload());

        if (!returnRTOnly) {
            JSONObject md = rtiResponse.getUserMetadata();
            newIDTX.setStoredToken(rtiResponse.getIdToken().getToken());
            md.put(JWT_ID, newIDTX.getIdentifier().toString()); // reset the returned ID.
            debugger.trace(this, "Processed id token return type");

            HashSet<String> allowedScopes = new HashSet<>();
            HashSet<String> newScopeSet = new HashSet<>();
            allowedScopes.addAll(((OA2Client) t.getClient()).getScopes()); // Scopes the ersatz client is actually allowed
            newScopeSet.addAll(t.getScopes()); // scopes that the provisioning client requested
            newScopeSet.retainAll(allowedScopes);
            t.setScopes(newScopeSet);
            newScopeSet.addAll(OA2Scopes.ScopeUtil.toScopes(t.getATData().getString(OA2Constants.SCOPE)));
            t.setScopes(newScopeSet); // ???? Is this right?  Does this ignore OIDC scopes, e.g. openid?
            debugger.trace(this, "setting ersatz client scopes to " + newScopeSet);
        }
        if (returnRTOnly) {
            rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().getToken()); // Required.
            rfcClaims.put(EXPIRES_IN, rtiResponse.getRefreshToken().getLifetime() / 1000);

            if (client.isRTLifetimeEnabled() && rtiResponse.hasRefreshToken()) {
                t.setRTData(rtiResponse.getRefreshToken().getPayload());
                t.setRTJWT(rtiResponse.getRefreshToken().getToken());
            }
        } else {
            updateTransactionJWTFromTokenResponse(rtiResponse, t, client);
            if (((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().getToken()); // Required.
                newATTX.setStoredToken(rtiResponse.getAccessToken().getToken());
            } else {
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().encodeToken()); // Required.
            }
            rfcClaims.put(EXPIRES_IN, rtiResponse.getAccessToken().getLifetime() / 1000);

            rfcClaims.put(OA2Constants.ID_TOKEN, rtiResponse.getIdToken().getToken());

        }

        // Now set the payloads for the response.
        if (rtiResponse.getRefreshToken().isJWT()) {
            rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().getToken()); // Optional
            newRTTX.setStoredToken(rtiResponse.getRefreshToken().getToken());
        } else {
            rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Optional
        }
        getTransactionStore().save(t);

        debugger.trace(this, "rfc claims returned:" + rfcClaims.toString(1));
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        PrintWriter osw = response.getWriter();
        rfcClaims.write(osw);
        osw.flush();
        osw.close();


    }

    private void doRFC8693Exchange(RFC8693Thingie rfc8693Thingie,
                                   HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {
        OA2ServiceTransaction t = rfc8693Thingie.transaction;
        OA2Client client = rfc8693Thingie.client;
        if (client.isErsatzClient()) {
            client = OA2ClientUtils.createErsatz(getOA2SE(), t, client);
/*
            Permission ersatzChain = getOA2SE().getPermissionStore().getErsatzChain(t.getProvisioningAdminID(), t.getProvisioningClientID(), client.getIdentifier());
            client = OA2ClientUtils.createErsatz(t.getProvisioningClientID(), getOA2SE(), client, ersatzChain.getErsatzChain());
*/
        }
        MetaDebugUtil debugger = rfc8693Thingie.debugger;
        String requestedTokenType = rfc8693Thingie.requestTokenType;
        List<String> scopes = rfc8693Thingie.scopes;
        List<String> audience = rfc8693Thingie.audience;
        List<String> resources = rfc8693Thingie.resources;
        OA2SE oa2se = getOA2SE();

        XMLMap tBackup = GenericStoreUtils.toXML(getTransactionStore(), t);
        OA2ServletUtils.processXAs(request, t, client);
/*
        if (client.hasExtendedAttributeSupport()) {
            ExtendedParameters xp = new ExtendedParameters();
            // Take the parameters and parse them into configuration objects,
            JSONObject extAttr = xp.snoopParameters(request.getParameterMap());
            if (extAttr != null && !extAttr.isEmpty()) {
                t.setExtendedAttributes(extAttr);
            }
        }
*/
        // In practice exactly one of these is active at any given time
        TXRecord newIDTX = null;
        TXRecord newATTX = null;
        TXRecord newRTTX = null;
        TXRecord activeTX = null;

        switch (requestedTokenType) {
            case RFC8693Constants.ID_TOKEN_TYPE:
                if (!client.isOIDCClient()) {
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                            "identity tokens not supported for this client",
                            t.getRequestState());
                }
                if (!getOA2SE().isOIDCEnabled()) {
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                            "identity tokens not supported on this server",
                            t.getRequestState());
                }
                newIDTX = (TXRecord) oa2se.getTxStore().create();
                newIDTX.setIdentifier(((OA2TokenForge) oa2se.getTokenForge()).getIDTokenProvider().get());
                newIDTX.setTokenType(requestedTokenType);
                newIDTX.setParentID(t.getIdentifier());
                newIDTX.setIssuedAt(System.currentTimeMillis());
                activeTX = newIDTX;
                break;
            case RFC8693Constants.ACCESS_TOKEN_TYPE:
                newATTX = (TXRecord) oa2se.getTxStore().create();
                activeTX = newATTX;
                newATTX.setTokenType(requestedTokenType);
                newATTX.setParentID(t.getIdentifier());
                if (!audience.isEmpty()) {
                    newATTX.setAudience(audience);
                }
                if (!scopes.isEmpty()) {
                    debugger.trace(this, "user requested scopes:" + scopes);
                    newATTX.setScopes(scopes);
                } else {
                    // If no scopes sent with request, revert to scopes in original request.
                    debugger.trace(this, "NO user requested scopes");
                    //   newTXR.setScopes(t.getScopes());
                }

                if (!resources.isEmpty()) {
                    // convert to URIs
                    ArrayList<URI> r = new ArrayList<>();
                    for (String x : resources) {
                        try {
                            r.add(URI.create(x));
                        } catch (Throwable throwable) {
                            debugger.info(this, "rejected resource request \"" + x + "\"");
                            info("rejected resource request \"" + x + "\"");
                        }
                    }
                    newATTX.setResource(r);
                }
                newATTX.setIssuedAt(System.currentTimeMillis());
                break;
            case RFC8693Constants.REFRESH_TOKEN_TYPE:
                newRTTX = (TXRecord) oa2se.getTxStore().create();
                activeTX = newRTTX;
                newRTTX.setTokenType(requestedTokenType);
                newRTTX.setParentID(t.getIdentifier());
                newRTTX.setIssuedAt(System.currentTimeMillis());
                break;
        }

        RTIRequest rtiRequest = new RTIRequest(request, t, t.getAccessToken(), oa2se.isOIDCEnabled());
        RTI2 rtIssuer = new RTI2(getTF2(), OA4MPServlet.getServiceEnvironment().getServiceAddress());
        RTIResponse rtiResponse = (RTIResponse) rtIssuer.process(rtiRequest);
        debugger.trace(this, "rti response=" + rtiResponse);
        rtiResponse.setSignToken(client.isSignTokens());
        // These are the claims that are returned in the RFC's required response. They have nothing to do
        // with id token claims, fyi.
        JSONObject rfcClaims = new JSONObject();

        debugger.trace(this, "requested token type = " + requestedTokenType);
        // Implicitly again, forking the flow effectively means the token type is access and the client id is different
        switch (requestedTokenType) {
            case ACCESS_TOKEN_TYPE:
                // do NOT reset the refresh token
                // All the machinery from here out gets the RT from the rtiResponse.
                rfcClaims.put(ISSUED_TOKEN_TYPE, ACCESS_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_BEARER); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                newATTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getAccessToken().getToken()));
                newATTX.setExpiresAt(newATTX.getIssuedAt() + newATTX.getLifetime());
                rtiResponse.setRefreshToken(null); // no refresh token should get processed except in Ersatz case.
                activeTX = newATTX;
                debugger.trace(this, "Processed access token return type");

                break;
            case REFRESH_TOKEN_TYPE:
                rfcClaims.put(ISSUED_TOKEN_TYPE, REFRESH_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_N_A); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                newRTTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getRefreshToken().getToken()));
                newRTTX.setExpiresAt(newRTTX.getIssuedAt() + newRTTX.getLifetime());
                activeTX = newRTTX;
                debugger.trace(this, "Processed refresh token return type");
                break;
            case ID_TOKEN_TYPE:
                rfcClaims.put(ISSUED_TOKEN_TYPE, ID_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, TOKEN_TYPE_N_A); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                newIDTX.setExpiresAt(newIDTX.getIssuedAt() + newIDTX.getLifetime());
                activeTX = newIDTX;
                // Have to run handlers to update ID token.
                break;
            default:
                throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                        "unknown requested token type",
                        t.getRequestState());
        }

        HandlerRunner handlerRunner = new HandlerRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2se, t, activeTX, client.getConfig()));
        try {
            OA2ClientUtils.setupHandlers(handlerRunner, oa2se, t, client, newIDTX, newATTX, newRTTX, request);
            // NOTE WELL that the next two lines are where our identifiers are used to create JWTs (like SciTokens)
            // so if this is not done, the wrong token type will be returned.
            handlerRunner.doTokenExchange();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2se, throwable, debugger, t, tBackup, activeTX);
        }

        setupTokenResponseFromRunner(client, rtiResponse, oa2se, t, handlerRunner, true, debugger);
        debugger.trace(this, "rtiResponse after token setup:" + rtiResponse);
        switch (requestedTokenType) {
            case ACCESS_TOKEN_TYPE:
                if (((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().getToken()); // Required.
                    newATTX.setStoredToken(rtiResponse.getAccessToken().getToken());
                } else {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().encodeToken()); // Required.
                }
                // https://jira.ncsa.illinois.edu/browse/CIL-2019
                rfcClaims.put(EXPIRES_IN, rtiResponse.getAccessToken().getLifetime() / 1000);
                // create scope string  Remember that these may have been changed by a script,
                // so here is the right place to set it.
                rfcClaims.put(OA2Constants.SCOPE, listToString(newATTX.getScopes()));
                break;
            case REFRESH_TOKEN_TYPE:
                if (rtiResponse.getRefreshToken().isJWT()) {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().getToken()); // Required
                    rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().getToken()); // Optional
                    newRTTX.setStoredToken(rtiResponse.getRefreshToken().getToken());
                } else {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Required
                    rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Optional
                }
                // https://jira.ncsa.illinois.edu/browse/CIL-2019
                rfcClaims.put(EXPIRES_IN, rtiResponse.getRefreshToken().getLifetime() / 1000);

                long gracePeriod = ClientUtils.computeRTGracePeriod(client, oa2se);
                long expiresAt = System.currentTimeMillis() + gracePeriod;
                if (rfc8693Thingie.oldRTTX == null) {
                    // change the expiration time in the transaction itself
                    t.setRefreshTokenExpiresAt(expiresAt);
                } else {
                    rfc8693Thingie.oldRTTX.setExpiresAt(expiresAt);
                    rfc8693Thingie.oldRTTX.setLifetime(gracePeriod);

                    oa2se.getTxStore().save(rfc8693Thingie.oldRTTX);
                }
                break;
            case ID_TOKEN_TYPE:
                JSONObject md = rtiResponse.getUserMetadata();
                newIDTX.setStoredToken(rtiResponse.getIdToken().getToken());
                md.put(JWT_ID, newIDTX.getIdentifier().toString()); // reset the returned ID.
                debugger.trace(this, "Processed id token return type");
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getIdToken().getToken());
                // https://jira.ncsa.illinois.edu/browse/CIL-2019
                rfcClaims.put(EXPIRES_IN, rtiResponse.getIdToken().getLifetime() / 1000);
        }

        debugger.trace(this, "rfc claims returned:" + rfcClaims.toString(1));
        /*

         Important note: In the RFC 8693 spec., access_token MUST be returned, however, it explains that this
         is so named merely for compatibility with OAuth 2.0 request/response constructs. The actual
         content of this is undefined.

         Our policy: access_token contains whatever the requested token is. Look at the returned_token_type
         to see what they got. As a convenience, if there is a refresh token, that will be returned as the
         refresh_token claim.

         Ersatz clients should return both the access token and a new refresh token.
         */

        // The other components (access, refresh token) have responses that handle setting the encoding and
        // char type. We have to set it manually here.
        response.setContentType("application/json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");
        /*
        As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

         The authorization server MUST include the HTTP "Cache-Control"
         response header field [RFC2616] with a value of "no-store" in any
         response containing tokens, credentials, or other sensitive
         information, as well as the "Pragma" response header field [RFC2616]
         with a value of "no-cache".
         */
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");

        if (newIDTX != null) {
            newIDTX.setValid(true);
            oa2se.getTxStore().save(newIDTX);
            // t.setUserMetaData(jwtRunner.getIdTokenHandlerInterface().getUserMetaData());
        }
        if (newATTX != null) {
            if (!((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
                // native OA4MP token, set accounting info here.
                AccessTokenImpl at = (AccessTokenImpl) rtiResponse.getAccessToken();
                newATTX.setIssuedAt(at.getIssuedAt());
                newATTX.setLifetime(at.getLifetime());
                newATTX.setExpiresAt(at.getExpiresAt());
            }
            newATTX.setValid(true);
            oa2se.getTxStore().save(newATTX);
            // t.setATData(jwtRunner.getAccessTokenHandler().getPayload());
        }
        if (newRTTX != null) {
            if (rtiResponse.hasRefreshToken() && !rtiResponse.getRefreshToken().isJWT()) {
                // native OA4MP token, set accounting info here.
                RefreshTokenImpl rt = rtiResponse.getRefreshToken();
                newRTTX.setIssuedAt(rt.getIssuedAt());
                newRTTX.setLifetime(rt.getLifetime());
                newRTTX.setExpiresAt(rt.getExpiresAt());
            }
            newRTTX.setValid(true);
            oa2se.getTxStore().save(newRTTX);
            //t.setRTData(jwtRunner.getRefreshTokenHandler().getPayload());
        }


        updateTransactionJWTFromTokenResponse(rtiResponse, t, client);
        getTransactionStore().save(t);
        PrintWriter osw = response.getWriter();
        debugger.trace(this, "Token exchange JSON:\n" + rfcClaims.toString(2));
        rfcClaims.write(osw);
        osw.flush();
        osw.close();
    }


    // Token exchange
    private void doRFC8693(OA2Client client,
                           HttpServletRequest request,
                           HttpServletResponse response) throws IOException {
        RFC8693Thingie rfc8693Thingie = startRFC8693(client, request, response);
        if (rfc8693Thingie.isErsatz) {
            doRFC8693Fork(rfc8693Thingie, request, response);
            return;
        }
        doRFC8693Exchange(rfc8693Thingie, request, response);
    }


    /**
     * Takes a substitution chain and does the overrides. Any int or long &lt; 0 is assumed unset
     * and is skipped.
     *
     * @param provisioningClientID
     * @param ersatzClient
     * @param ersatzChain
     * @return
     */
    protected OA2Client createErsatz(Identifier provisioningClientID, OA2Client ersatzClient, List<Identifier> ersatzChain) {
        //Moved this to the OA2ClientUtils where is should be.
        return OA2ClientUtils.createErsatz(provisioningClientID, getOA2SE(), ersatzClient, ersatzChain);
/*
        List<Identifier> prototypes = new ArrayList<>();
        if (ersatzClient.isExtendsProvisioners()) {
            prototypes.add(provisioningClientID); // this is normally not in the chain
            prototypes.addAll(ersatzChain.subList(0, ersatzChain.size() - 1)); // last element is ersatzClient, so skip
            prototypes.addAll(ersatzClient.getPrototypes());
            ersatzClient.setPrototypes(prototypes);
        }
        return OA2ClientUtils.resolvePrototypes(getOA2SE(), ersatzClient);
*/
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
            logOK(request); // CIL-1722
            return;
        }
        warn("grant type +\"" + grantType + "\" was not recognized. Request rejected.");
        throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                "unsupported grant type \"" + grantType + "\"");
    }

    @Override
    protected ATRequest getATRequest(HttpServletRequest request, ServiceTransaction transaction,
                                     OA2Client client) {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;
        // Set these in the transaction then send it along.
        t.setAccessTokenLifetime(ClientUtils.computeATLifetime(t, client, (OA2SE) OA4MPServlet.getServiceEnvironment()));
        if (client.isRTLifetimeEnabled()) {
            if (((OA2SE) OA4MPServlet.getServiceEnvironment()).isRefreshTokenEnabled()) {
                long lifetime = ClientUtils.computeRefreshLifetime(t, client, (OA2SE) OA4MPServlet.getServiceEnvironment());
                t.setRefreshTokenLifetime(lifetime);
                t.setRefreshTokenExpiresAt(System.currentTimeMillis() + lifetime);
            }
        } else {
            t.setRefreshTokenLifetime(0L);
            t.setMaxRTLifetime(0L);
        }

        ATRequest atRequest = new ATRequest(request, transaction);
        atRequest.setOidc(client.isOIDCClient());
        return atRequest;
    }

    @Override
    protected AuthorizationGrantImpl checkAGExpiration(AuthorizationGrant ag) {
        if (!ag.getToken().contains(Identifiers.VERSION_TAG)) {
            // update old version 1 token.
            AuthorizationGrantImpl ag0 = (AuthorizationGrantImpl) ag;
            ag0.setIssuedAt(DateUtils.getDate(ag0.getToken()).getTime());
            ag0.setLifetime(OA2ConfigurationLoader.AUTHORIZATION_GRANT_LIFETIME_DEFAULT);
            ag0.setVersion(Identifiers.VERSION_1_0_TAG);  // just in case.
            return ag0;
        }
        if (ag.isExpired()) {
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "grant expired");
        }
        return null;
    }

    protected OA2SE getOA2SE() {
        return (OA2SE) OA4MPServlet.getServiceEnvironment();
    }

    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = doDelegation(client, request, response);
        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) state.getTransaction();
        String verifier = request.getParameter(RFC7636Util.CODE_VERIFIER);
        checkCodeChallenge(serviceTransaction, client, verifier);
        return doAT(state, client);
    }

    protected void checkCodeChallenge(OA2ServiceTransaction serviceTransaction, OA2Client client, String verifier) {
        if (serviceTransaction.hasCodeChallenge()) {
            if (StringUtils.isTrivial(verifier)) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "missing verifier, access denied",
                        serviceTransaction.getRequestState());
            }
            String codeChallenge = RFC7636Util.createChallenge(verifier, serviceTransaction.getCodeChallengeMethod());
            if (StringUtils.isTrivial(codeChallenge)) {
                // CIL-1307
                OA4MPServlet.createDebugger(client).trace(this, "Missing verifier, PKCE (RFC 7636) failed");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "bad or missing code challenge, access denied",
                        serviceTransaction.getRequestState());
            }
            if (!codeChallenge.equals(serviceTransaction.getCodeChallenge())) {
                // CIL-1307
                OA4MPServlet.createDebugger(client).trace(this, "missing code challenge, PKCE (RFC 7636) failed");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "code challenge failed, access denied",
                        serviceTransaction.getRequestState());
            }
        } else {
            if (getOA2SE().isRfc7636Required() && client.isPublicClient()) {
                OA4MPServlet.createDebugger(client).trace(this, "public client failed to send required code challenge, PKCE (RFC 7636) failed.");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "code challenge failed, access denied",
                        serviceTransaction.getRequestState());
            }
        }
    }

    protected IssuerTransactionState doAT(IssuerTransactionState state, OA2Client client) throws Throwable {
        // Grants are checked in the doIt method
        XMLMap tBackup = state.getBackup(); // stash it here.
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();

        atResponse.setSignToken(client.isSignTokens());
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();

        OA2ServiceTransaction st2 = (OA2ServiceTransaction) state.getTransaction();
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(st2.getClient());
        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(st2);
        }
        if (getOA2SE().hasAuthorizationServletConfig() && getOA2SE().getAuthorizationServletConfig().isLocalDFConsent() && !st2.isConsentPageOK()) {
            throw new OA2ATException(OA2Errors.CONSENT_REQUIRED,
                    "consent required",
                    HttpStatus.SC_BAD_REQUEST,
                    null,
                    st2.getClient());
        }
        debugger.trace(this, "starting to get access token ");
        if (!st2.getFlowStates().acceptRequests || !st2.getFlowStates().accessToken || !st2.getFlowStates().idToken) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    st2.getRequestState());
        }
        // Wrong client means we just blow up since we don't want to return anything at all about
        // the original client or the state of any transactions.
        if (!st2.getClient().getIdentifierString().equals(client.getIdentifierString())) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "wrong client, access denied",
                    HttpStatus.SC_UNAUTHORIZED, null);
        }

        st2.setAccessToken(atResponse.getAccessToken()); // needed if there are handlers later.

        /* *************** */
        // CIL-1536 -- use tx record for forwarding any parameters to the runtime engine.

        List<String> scopes = convertToList(state.getRequest(), OA2Constants.SCOPE);
        List<String> audience = convertToList(state.getRequest(), AUDIENCE);
        List<String> resources = convertToList(state.getRequest(), RESOURCE);
        boolean gotRequestParam = !(scopes.isEmpty() && audience.isEmpty() && resources.isEmpty());
        TXRecord atTX = null;
        TXRecord rtTX = null;
        if (gotRequestParam) {
            // Big thing is the scopes. If the scopes requested are the same as the original scopes,
            // skip processing scopes.
            // Case to handle: NO scopes in AuthZ, but scopes here. Perfectly legal from OAuth 2 spec.

            if (!scopes.isEmpty()) {
                if (st2.getScopes().isEmpty()) {
                    st2.setScopes(ClientUtils.resolveScopes(state, st2.getOA2Client(), false, false));
                } else {
                    // actual check if requested scopes are a subset of authz scopes
                    HashSet<String> originalScopes = new HashSet<>();
                    HashSet<String> requestedScopes = new HashSet<>();
                    originalScopes.addAll(st2.getScopes());
                    requestedScopes.addAll(scopes);
                    if (!originalScopes.equals(requestedScopes)) {
                        atTX = (TXRecord) oa2SE.getTxStore().create();
                        atTX.setScopes(scopes);
                    }
                }
            }
            if (!audience.isEmpty()) {
                if (atTX == null) {
                    atTX = (TXRecord) oa2SE.getTxStore().create();
                }
                atTX.setAudience(audience);
            }
            if (!resources.isEmpty()) {
                // convert to URIs
                ArrayList<URI> r = new ArrayList<>();
                for (String x : resources) {
                    try {
                        r.add(URI.create(x));
                    } catch (Throwable throwable) {
                        debugger.info(this, "rejected resource request \"" + x + "\"");
                        info("rejected resource request \"" + x + "\"");
                    }
                }
                if (atTX == null) {
                    atTX = (TXRecord) oa2SE.getTxStore().create();
                }
                atTX.setResource(r);
            }
        }
        if (atTX != null) {
            // We are not going to save the TX record because we don't need it for mare than transmitting
            // overrides in scope, audience and resource to the handlers to QDL. It does have to look exactly
            // like any other TXRecords, so set the identifier and type.

            atTX.setTokenType(ACCESS_TOKEN_TYPE); // Ensure that handlers can recognize this for access tokens.
            atTX.setIdentifier(BasicIdentifier.newID(atResponse.getAccessToken().getToken()));
        }
        /* *************** */

        if (client.isRTLifetimeEnabled()) {
            st2.setRefreshToken(atResponse.getRefreshToken()); // ditto. Might be null.
        } else {
            st2.setRefreshToken(null);
            st2.setRefreshTokenLifetime(0L);
        }
        HandlerRunner handlerRunner = new HandlerRunner(st2, ScriptRuntimeEngineFactory.createRTE(oa2SE, st2, atTX, client.getConfig()));
        OA2ClientUtils.setupHandlers(handlerRunner, oa2SE, st2, client, null, atTX, rtTX, state.getRequest());
        if (state.isRfc8628() || st2.getAuthorizationGrant().getVersion() == null || st2.getAuthorizationGrant().getVersion().equals(Identifiers.VERSION_1_0_TAG)) {
            // Handlers have not been initialized yet. Either because of old tokens or rfc 8628 (so no tokens).
            handlerRunner.initializeHandlers();
        }
        try {
            handlerRunner.doTokenClaims();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2SE, throwable, createDebugger(st2.getClient()), st2, tBackup);
        }

        if (client.isRTLifetimeEnabled()) {
            st2.setRefreshTokenValid(true); // didn't blow up, set valid
        } else {
            atResponse.setRefreshToken(null);
        }
        setupTokenResponseFromRunner(client, atResponse, oa2SE, st2, handlerRunner, debugger);
        AccessTokenImpl tempAT = (AccessTokenImpl) atResponse.getAccessToken();
        if (tempAT.isJWT()) {
            st2.setATJWT(tempAT.getToken());
        }
        RefreshTokenImpl tempRT = atResponse.getRefreshToken();
        if (tempRT != null && tempRT.isJWT()) {
            st2.setRTJWT(tempRT.getToken());
        }
        debugger.trace(this, "got access token for transaction=" + st2.summary());
        // only do this before last save, so if the whole thing bombs, they can try again
        st2.setAuthGrantValid(false);
        // https://github.com/ncsa/oa4mp/issues/128

        updateTransactionJWTFromTokenResponse(atResponse, st2, client);
        if (st2.getATData().containsKey(OA2Constants.SCOPE)) {
            st2.setATReturnedOriginalScopes(st2.getATData().getString(OA2Constants.SCOPE));
        }
        getTransactionStore().save(st2);
        // Check again after doing token claims in case a script changed it.
        // If they fail at this point, access it denied and the tokens are invalidated.
        if (!st2.getFlowStates().acceptRequests || !st2.getFlowStates().accessToken || !st2.getFlowStates().idToken) {
            throw new OA2ATException(
                    OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    st2.getRequestState());
        }
        return state;
    }

    /**
     * This updates the service transaction UMD, AT and RT JSONObjects (if any) from the {@link IDTokenResponse} and if needed
     * sets the id of the UMD.
     */
    private static void updateTransactionJWTFromTokenResponse(IDTokenResponse tokenResponse,
                                                              OA2ServiceTransaction st2,
                                                              OA2Client client) {
        st2.setUserMetaData(tokenResponse.getIdToken().getPayload());
        st2.setATData(tokenResponse.getAccessToken().getPayload());
        st2.setATJWT(tokenResponse.getAccessToken().getToken());
        if (client.isRTLifetimeEnabled() && tokenResponse.hasRefreshToken()) {
            st2.setRTData(tokenResponse.getRefreshToken().getPayload());
            st2.setRTJWT(tokenResponse.getRefreshToken().getToken());
        }
        if (st2.getUserMetaData().containsKey(JWT_ID)) {
            st2.setIDTokenIdentifier(st2.getUserMetaData().getString(JWT_ID));
        }
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
     * @param handlerRunner
     */
    private void setupTokenResponseFromRunner(OA2Client client,
                                              IDTokenResponse tokenResponse,
                                              OA2SE oa2SE,
                                              OA2ServiceTransaction st2,
                                              HandlerRunner handlerRunner, MetaDebugUtil debugger) {
        setupTokenResponseFromRunner(client, tokenResponse, oa2SE, st2, handlerRunner, false, debugger);
    }

    /**
     * Takes the newly modified access and refresh tokens after all scripts are run
     * and updates the token reponse so that whatever the script did is not stored in the system.
     *
     * @param client
     * @param tokenResponse
     * @param oa2SE
     * @param st2
     * @param handlerRunner
     * @param isTokenExchange
     */
    private void setupTokenResponseFromRunner(OA2Client client,
                                              IDTokenResponse tokenResponse,
                                              OA2SE oa2SE,
                                              OA2ServiceTransaction st2,
                                              HandlerRunner handlerRunner,
                                              boolean isTokenExchange,
                                              MetaDebugUtil debugger
    ) {
        if (debugger == null) {
            debugger = OA4MPServlet.createDebugger(client);
        }
        VirtualIssuer vo = oa2SE.getVI(client.getIdentifier());
        JSONWebKey key = null;
        if (vo != null && vo.getJsonWebKeys() != null) {
            key = vo.getJsonWebKeys().get(vo.getDefaultKeyID());
        } else {
            key = oa2SE.getJsonWebKeys().getDefault();
        }
        if (handlerRunner.hasATHandler()) {
            AccessTokenImpl newAT = (AccessTokenImpl) handlerRunner.getAccessTokenHandler().getSignedPayload(key);
            debugger.trace(this, "jwt has at handler: at=" + newAT + ", for claims " + st2.getATData().toString(2));
            tokenResponse.setAccessToken(newAT);
            debugger.trace(this, "Returned AT from handler:" + newAT + ", for claims " + st2.getATData().toString(2));
            // update the id token handler if this has been updated elsewhere.
            handlerRunner.getIdTokenHandlerInterface().setUserMetaData(handlerRunner.getAccessTokenHandler().getUserMetaData());
        } else {
            debugger.trace(this, "NO ATHandler in jwtRunner");
        }
        if (handlerRunner.hasIDTokenHandler()) {
            tokenResponse.setUserMetadata(handlerRunner.getIdTokenHandlerInterface().getUserMetaData());
            tokenResponse.setIdToken(((IDTokenHandler) handlerRunner.getIdTokenHandlerInterface()).getSignedPayload(key));
        }

        debugger.trace(this, "set token signing flag =" + tokenResponse.isSignToken());
        // no processing of the refresh token is needed if there is none.
        if (!tokenResponse.hasRefreshToken()) {
            debugger.trace(this, "token response has no refresh token.");
            return;
        }
        if (!client.isRTLifetimeEnabled() && oa2SE.isRefreshTokenEnabled()) {
            // Since this bit of information could be extremely useful if a service decides
            // to start issuing refresh tokens after
            // clients have been registered, it should be logged.
            debugger.info(this, "Refresh tokens are disabled for client " + client.getIdentifierString() + ", but enabled on the server. No refresh token will be made.");
            info("Refresh tokens are disabled for client " + client.getIdentifierString() + ", but enabled on the server. No refresh token will be made.");
        }
        if (client.isRTLifetimeEnabled() && oa2SE.isRefreshTokenEnabled()) {
            RefreshTokenImpl rt = tokenResponse.getRefreshToken();
            // rt is used as a key in the database. If the refresh token is  JWT, it will be used as the jti.
          /*  if (!isTokenExchange) {
                st2.setRefreshToken(rt);
                st2.setRefreshTokenValid(true);
            }*/
            if (handlerRunner.hasRTHandler()) {
                RefreshTokenImpl newRT = (RefreshTokenImpl) handlerRunner.getRefreshTokenHandler().getSignedPayload(null); // unsigned, for now
                tokenResponse.setRefreshToken(newRT);
                debugger.trace(this, "Returned RT from handler:" + newRT + ", for claims " + st2.getRTData().toString(2));
            }
            debugger.trace(this, "setting refresh token to " + st2.getRefreshToken().getToken());
        } else {
            // Even if a token is sent, do not return a refresh token.
            // This might be in a legacy case where a server changes it policy to prohibit  issuing refresh tokens but
            // an outstanding transaction has one.
            debugger.trace(this, "setting refresh token to null");
            tokenResponse.setRefreshToken(null);
        }
    }


    protected OA2ServiceTransaction getByRT(RefreshToken refreshToken) throws IOException {
        if (refreshToken == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing refresh token");
        }
        RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
        try {
            JSONObject jsonObject = MyOtherJWTUtil2.verifyAndReadJWT(refreshToken.getToken(), ((OA2SE) OA4MPServlet.getServiceEnvironment()).getJsonWebKeys());
            if (jsonObject.containsKey(JWT_ID)) {
                refreshToken = TokenFactory.createRT(jsonObject);
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
        return (OA2TokenForge) OA4MPServlet.getServiceEnvironment().getTokenForge();
    }

    protected TransactionState doRefresh(OA2Client client, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        return doNEWRefresh(client, request, response);
    }

    protected TransactionState doNEWRefresh(OA2Client client, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Grants are checked in the doIt method
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(client);
        printAllParameters(request, debugger);
        String rawRefreshToken = request.getParameter(OA2Constants.REFRESH_TOKEN);
        if (StringUtils.isTrivial(rawRefreshToken)) {
            // Then this request is, in fact, invalid.
            // Fix https://github.com/ncsa/oa4mp/issues/166
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing refresh token");

        }
        if (client == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "Could not find the client associated with refresh token \"" + rawRefreshToken + "\"");
        }
        debugger.trace(this, "starting token refresh at " + (new Date()));
        // Check if it's a token or JWT
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();
        //CIL-974:
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, client);
        RefreshTokenImpl oldRT;
        boolean tokenVersion1 = false;
        // request always sends the RT. This recovers the transactions from the TX record if needed.
        try {
            oldRT = OA2TokenUtils.getRT(rawRefreshToken, oa2SE, keys, debugger);
        } catch (OA2GeneralError oa2ATException) {
            info(oa2ATException.getError() + " in refresh for client " + client.getIdentifierString());
            oa2ATException.setClient(client);
            throw oa2ATException;
        }
        OA2ServiceTransaction t = null;
        TXRecord oldTXRT = null;
        try {
            // Fix for CIL-882
            t = getByRT(oldRT);
            if (!t.getClient().getIdentifier().equals(client.getIdentifier())) {
                debugger.trace(this, "transaction lists client id \"" + t.getClient().getIdentifierString()
                        + "\", but the client in the request is \"" + client.getIdentifierString() + "\". Request rejected.");
                OA2ATException x = new OA2ATException(OA2Errors.INVALID_GRANT, // fixes https://github.com/ncsa/oa4mp/issues/119
                        "wrong client",
                        HttpStatus.SC_BAD_REQUEST, null);
                x.setForensicMessage("expected client \"" + client.getIdentifierString() + "\" but got client \"" + t.getClient().getIdentifierString() + "\"");
                x.setClient(client);
                throw x;

            }
        } catch (TransactionNotFoundException e) {
            t = OA2TokenUtils.getTransactionFromTX(oa2SE, oldRT, debugger);
            if (t == null) {
                String message = "The refresh token \"" + oldRT.getToken() + "\" for client " + client.getIdentifierString() + " is not expired, but also was not found.";
                debugger.info(this, message);
                OA2ATException x = new OA2ATException(OA2Errors.INVALID_TOKEN, "The token could not be associated with a pending flow",
                        HttpStatus.SC_BAD_REQUEST, null);
                x.setClient(client);
                x.setForensicMessage("token cannot be associated witH a pending flow:" + oldRT);
                throw x;
            }
            oldTXRT = (TXRecord) getOA2SE().getTxStore().get(BasicIdentifier.newID(oldRT.getJti()));
        }
        if (client.isErsatzClient()) {
            Permission ersatzChain = getOA2SE().getPermissionStore().getErsatzChain(t.getProvisioningAdminID(), t.getProvisioningClientID(), client.getIdentifier());
            client = OA2ClientUtils.createErsatz(t.getProvisioningClientID(), getOA2SE(), client, ersatzChain.getErsatzChain());
        }
        XMLMap backup = GenericStoreUtils.toXML(getTransactionStore(), t);
        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(t);
        }
        if (tokenVersion1) {
            // Can't fix it until we have the right transaction.
            long rtL = ClientUtils.computeRefreshLifetime(t, client, oa2SE);
            t.setRefreshTokenLifetime(rtL);
            t.setRefreshTokenExpiresAt(System.currentTimeMillis() + rtL);
            t.setAccessTokenLifetime(ClientUtils.computeATLifetime(t, client, oa2SE));
        }

        if (t == null || !t.isRefreshTokenValid()) {
            debugger.trace(this, "Missing refresh token.");
            OA2ATException x = new OA2ATException(OA2Errors.INVALID_REQUEST,
                    "The refresh token is no longer valid.",
                    t.getRequestState());
            x.setForensicMessage("the token is invalid:" + oldRT);
            x.setClient(client);
            throw x;
        }
        OA2ServletUtils.processXAs(request, t, client);
/*
        if (client.hasExtendedAttributeSupport()) {
            ExtendedParameters xp = new ExtendedParameters();
            // Take the parameters and parse them into configuration objects,
            JSONObject extAttr = xp.snoopParameters(request.getParameterMap());
            if (extAttr != null && !extAttr.isEmpty()) {
                t.setExtendedAttributes(extAttr);
            }
        }
*/
        AccessTokenImpl at = (AccessTokenImpl) t.getAccessToken();
        debugger.trace(this, "old access token = " + at.getToken());
        List<String> scopes = convertToList(request, OA2Constants.SCOPE);
        List<String> audience = convertToList(request, AUDIENCE);
        List<URI> resources = convertToURIList(request, RESOURCE);


        debugger.trace(this, "flow states = " + t.getFlowStates());
        if (!t.getFlowStates().acceptRequests || !t.getFlowStates().refreshToken) {
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "Refresh token access denied.",
                    t.getRequestState());
        }
        if ((!(oa2SE).isRefreshTokenEnabled()) || (!client.isRTLifetimeEnabled())) {
            throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                    "Refresh tokens are not supported on this server.",
                    t.getRequestState());
        }

        RTIRequest rtiRequest = new RTIRequest(request, t, at, oa2SE.isOIDCEnabled() && client.isOIDCClient());
        RTI2 rtIssuer = new RTI2(getTF2(), OA4MPServlet.getServiceEnvironment().getServiceAddress());

        RTIResponse rtiResponse = (RTIResponse) rtIssuer.process(rtiRequest);
        rtiResponse.setSignToken(client.isSignTokens());

        debugger.trace(this, "rt issuer response: " + rtiResponse);

        // Note for CIL-525: Here is where we need to recompute the claims. If a request comes in for a new
        // refresh token, it has to be checked against the recomputed claims. Use case is that a very long-lived
        // refresh token is issued, a user is no longer associated with a group and her access is revoked, then
        // attempts to get another refresh token (e.g. by some automated service everyone forgot was running) should fail.
        // Which claims to recompute? All of them? It is possible that there are several sources that need to be taken in to
        // account that may not be available, e.g. if there are shibboleth headers as in initial source...
        // Executive decision is to re-run the sources from after the bootstrap. The assumption with bootstrap sources
        // is that they exist only for the initialization.

        // have to set the AT here or the meta data won't get updated in the handler
        // CIL-1266

        TXRecord txAT = (TXRecord) oa2SE.getTxStore().create();
        txAT.setTokenType(ACCESS_TOKEN_TYPE);
        txAT.setParentID(t.getIdentifier());
        txAT.setIdentifier(rtiResponse.getAccessToken().getJTIAsIdentifier());
        txAT.setScopes(scopes);

        TXRecord txRT = null;

        if (t.getOA2Client().isRTLifetimeEnabled()) {
            txRT = (TXRecord) oa2SE.getTxStore().create();
            txRT.setTokenType(REFRESH_TOKEN_TYPE);
            txRT.setParentID(t.getIdentifier());
            txRT.setIdentifier(rtiResponse.getRefreshToken().getJTIAsIdentifier());
        }


        TXRecord txIDT = (TXRecord) oa2SE.getTxStore().create();
        txIDT.setTokenType(ID_TOKEN_TYPE);
        txIDT.setParentID(t.getIdentifier());
        Identifier newIDTokenID = ((OA2TokenForge) getOA2SE().getTokenForge()).getIDTokenProvider().get();
        txIDT.setIdentifier(newIDTokenID); // new ID
        // only set the access token properties if there is something there
        if (!scopes.isEmpty() || !audience.isEmpty() || !resources.isEmpty()) {
            txAT.setAudience(audience);
            txAT.setResource(resources);
        }
    /*    if (scopes == null || scopes.isEmpty()) {
            scopes = new ArrayList<>();
            scopes.addAll(t.getScopes()); // default to original
        }*/
        if (scopes == null) {
            scopes = new ArrayList<>();
            //scopes.addAll(t.getScopes()); // default to original
        }
        txAT.setScopes(scopes);
        txIDT.setScopes(scopes);
        if (txRT != null) {
            txRT.setScopes(scopes);
        }

        getOA2SE().getTxStore().save(txAT);
        if (txRT != null) {
            getOA2SE().getTxStore().save(txRT);
        }
        getOA2SE().getTxStore().save(txIDT);

        debugger.trace(this, "set new access token = " + rtiResponse.getAccessToken().getToken());
        // remember that the client may have been resolved from prototypes, so use the one passed in, not in the transaction.
        HandlerRunner handlerRunner = new HandlerRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, txAT, client.getConfig()));
        OA2ClientUtils.setupHandlers(handlerRunner, oa2SE, t, client, txIDT, txAT, txRT, request);

        try {
            handlerRunner.doRefreshClaims();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2SE, throwable, createDebugger(client), t, backup, txAT);
        }
        setupTokenResponseFromRunner(client, rtiResponse, oa2SE, t, handlerRunner, debugger);

        debugger.trace(this, "finished processing claims.");

        // At this point, key in the transaction store is the grant, so changing the access token
        // over-writes the current value. This practically invalidates the previous access token.
        //   getTransactionStore().remove(t.getIdentifier()); // this is necessary to clear any caches.
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
        VirtualIssuer vo = oa2SE.getVI(client.getIdentifier());

        if (vo == null) {
            rtiResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        } else {
            rtiResponse.setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        if (txIDT == null) {
            rtiResponse.setUserMetadata(t.getUserMetaData());
        } else {
            rtiResponse.setUserMetadata(txIDT.getToken());
        }

        if (txRT != null && rtiResponse.getRefreshToken().isJWT()) {
            if (rtiResponse.getRefreshToken().isJWT()) {
                txRT.setStoredToken(rtiResponse.getRefreshToken().getToken());
            } else {

            }
        }
        if (((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
            txAT.setStoredToken(rtiResponse.getAccessToken().getToken());
        } else {

        }
        // https://github.com/ncsa/oa4mp/issues/128
        // Using a new identifier for the ID token means that it is stored in a TX
        // record. We do this here.
        JSONObject newIDToken = rtiResponse.getUserMetadata();
        newIDToken.put(JWT_ID, newIDTokenID.toString());
        txIDT.setIdentifier(newIDTokenID);
        txIDT.setStoredToken(newIDToken.toString());
        if (oldTXRT == null) {
            // Have to invalidate it in the transaction.
            long gracePeriod = ClientUtils.computeRTGracePeriod(client, oa2SE);
            if (0 <= gracePeriod) {
                t.setRefreshTokenExpiresAt(System.currentTimeMillis() + gracePeriod);
            }

        } else {
            // only alter record to new grace period if we get this far, since otherwise we might invalidate their token
            // early.
            long gracePeriod = ClientUtils.computeRTGracePeriod(client, oa2SE);
            if (0 <= gracePeriod) {
                // If this is non-negative, then it has been configured. Not configured = let everything expire normally.
                oldTXRT.setExpiresAt(System.currentTimeMillis() + gracePeriod);
                oldTXRT.setLifetime(gracePeriod);
                //       oldTXRT.setValid(0 != gracePeriod); // Valid if non-zero. Zero means invalidate asap.
                getOA2SE().getTxStore().save(oldTXRT);
            }
        }
        // issue is that for TXRecords, the expiration has to be set.
        txAT.setValid(true); // Do not invalidate access tokens. Let them age naturally.
        txAT.setExpiresAt(System.currentTimeMillis() + ClientUtils.computeATLifetime(t, getOA2SE()));
        txIDT.setExpiresAt(System.currentTimeMillis() + ClientUtils.computeIDTLifetime(t, getOA2SE()));
        txIDT.setValid(true); // Do not invalidate access tokens. Let them age naturally.
        if (txRT != null) {
            txRT.setValid(true); // Do not invalidate access tokens. Let them age naturally.
            txRT.setExpiresAt(System.currentTimeMillis() + ClientUtils.computeRefreshLifetime(t, getOA2SE()));
            oa2SE.getTxStore().save(txRT);
        }
        updateTransactionJWTFromTokenResponse(rtiResponse, t, client);
        getTransactionStore().save(t);
        oa2SE.getTxStore().save(txAT);
        oa2SE.getTxStore().save(txIDT);
        debugger.trace(this, "transaction saved for " + t.getIdentifierString());

        /*
        As per https://datatracker.ietf.org/doc/html/rfc6749#section-5.1

         The authorization server MUST include the HTTP "Cache-Control"
         response header field [RFC2616] with a value of "no-store" in any
         response containing tokens, credentials, or other sensitive
         information, as well as the "Pragma" response header field [RFC2616]
         with a value of "no-cache".
         */
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        debugger.trace(this, "setting response headers.");
        rtiResponse.write(response);
        IssuerTransactionState state = new IssuerTransactionState(
                request,
                response,
                rtiResponse.getParameters(),
                t,
                backup,
                rtiResponse);
        debugger.trace(this, "done with token refresh, returning.");
        return state;
    } // end NEWdoRefresh


    protected void rollback(XMLMap backup) throws IOException {
        rollback(backup, null);
    }

    protected void rollback(XMLMap backup, TXRecord txRecord) throws IOException {
        if (backup.isEmpty()) {
            // there are a few cases (such as an RFC 7523 request where the transaction does not exist) where
            // we do not want a rollback.
            DebugUtil.trace(this, "no backup available");
            return;
        }
        GenericStoreUtils.fromXMLAndSave(getTransactionStore(), backup);
        if (txRecord != null) {
            getOA2SE().getTxStore().remove(txRecord.getIdentifier());
        }
    }

    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {

        ATIResponse2 atResponse = (ATIResponse2) iResponse;

        TransactionStore transactionStore = getTransactionStore();
        BasicIdentifier basicIdentifier = new BasicIdentifier(atResponse.getParameters().get(OA2Constants.AUTHORIZATION_CODE));
        ServletDebugUtil.trace(this, "getting transaction for identifier=" + basicIdentifier);
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
            String msg = "Attempt to use invalid authorization code \"" + basicIdentifier + "\".  Request rejected.";
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
        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();

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
        VirtualIssuer vo = oa2SE.getVI(transaction.getClient().getIdentifier());
        if (vo == null) {
            atResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        } else {
            atResponse.setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        atResponse.setUserMetadata(transaction.getUserMetaData());
        // Need to do some checking but for now, just return transaction
        //return null;
        return transaction;
    }

    @Override
    protected ServiceTransaction getTransaction(AuthorizationGrant ag, HttpServletRequest req) throws ServletException {

        OA2ServiceTransaction transaction = (OA2ServiceTransaction) OA4MPServlet.getServiceEnvironment().getTransactionStore().get(ag);
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(transaction.getOA2Client());
        if (transaction == null) {
            if (ag instanceof AuthorizationGrantImpl) {
                AuthorizationGrantImpl agi = (AuthorizationGrantImpl) ag;
                if (agi.isExpired()) {
                    debugger.trace(this, "Token \"" + ag.getToken() + "\" has expired");
                    throw new OA2ATException(OA2Errors.INVALID_GRANT,
                            "expired token");
                }
            }
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "invalid token");

        }
        if (!transaction.isAuthGrantValid()) {
            debugger.trace(this, "Token \"" + ag.getToken() + "\" is invalid");
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
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(client);
        printAllParameters(request, debugger);
        debugger.trace(this, "starting RFC 8628 access token exchange.");
        //  printAllParameters(request);
        long now = System.currentTimeMillis();
        String rawSecret = getClientSecret(request);
        if (!client.isPublicClient()) {
            verifyClient(client, request);
            //verifyClientSecret(client, rawSecret);
        }
        String deviceCode = request.getParameter(RFC8628Constants.DEVICE_CODE);
        if (StringUtils.isTrivial(deviceCode)) {
            debugger.trace(this, "missing " + RFC8628Constants.DEVICE_CODE + " parameter");
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "Missing " + RFC8628Constants.DEVICE_CODE + " parameter",
                    HttpStatus.SC_UNAUTHORIZED,
                    null);
        }
        URI ag;
        try {
            if (TokenUtils.isBase32(deviceCode)) {
                // CIL-1102 fix
                ag = URI.create(TokenUtils.b32DecodeToken(deviceCode));

            } else {
                ag = URI.create(deviceCode);
            }
        } catch (Throwable t) {
            debugger.info(this, "Failed to create " + RFC8628Constants.DEVICE_CODE + " from input \"" + deviceCode + "\"");
            info("Failed to create " + RFC8628Constants.DEVICE_CODE + " from input \"" + deviceCode + "\"");
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    RFC8628Constants.DEVICE_CODE + " is not a uri", HttpStatus.SC_UNAUTHORIZED, null);
        }
        AuthorizationGrantImpl authorizationGrant = new AuthorizationGrantImpl(ag);
        try {
            checkAGExpiration(authorizationGrant);
        } catch (OA2ATException atException) {
            // even though the token endpoint has a perfectly good way of communicating
            // that the token is expired, the RFC requires this instead
            debugger.trace(this, "expired token " + authorizationGrant.getToken());
            throw new OA2ATException("expired_token", RFC8628Constants.DEVICE_CODE + " expired");
        }
        OA2ServiceTransaction transaction = (OA2ServiceTransaction) getTransaction(authorizationGrant);

        if (transaction == null) {
            debugger.info(this, "Attempt to access RFC8628 end point by client, but no pending device flow found.");
            info("Attempt to access RFC8628 end point by client, but no pending device flow found.");
            throw new OA2ATException(OA2Errors.ACCESS_DENIED,
                    "no pending request", HttpStatus.SC_UNAUTHORIZED, null);
        }
        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(transaction);
        }
        XMLMap backup = GenericStoreUtils.toXML(getTransactionStore(), transaction);
        if (!transaction.isAuthGrantValid()) {
            throw new OA2ATException(OA2Errors.INVALID_GRANT,
                    "invalid device code",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }
        if (getOA2SE().hasAuthorizationServletConfig() && getOA2SE().getAuthorizationServletConfig().isLocalDFConsent() && !transaction.isConsentPageOK()) {
            throw new OA2ATException(OA2Errors.CONSENT_REQUIRED,
                    "consent required",
                    HttpStatus.SC_BAD_REQUEST,
                    null,
                    transaction.getClient());
        }

        if (!transaction.getClient().getIdentifierString().equals(client.getIdentifierString())) {
            throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "wrong client, access denied",
                    HttpStatus.SC_UNAUTHORIZED, transaction.getRequestState());
        }
        RFC8628State rfc8628State = transaction.getRFC8628State();
        if (rfc8628State.isExpired()) {
            // Odd case that it has expired, but the garbage collector has not disposed of it yet, for whatever reason.
            throw new OA2ATException(OA2Errors.ACCESS_DENIED, RFC8628Constants.DEVICE_CODE + " expired",
                    HttpStatus.SC_UNAUTHORIZED, null);
        }
        checkSentScopes(request, response, transaction);
        OA2ServletUtils.processXAs(request, transaction, client);

        // Logic is simple. If proxy, farm it out to the proxy and it works or doesn't.
        // otherwise, manage all the state for retries.
        if (getOA2SE().hasAuthorizationServletConfig() && getOA2SE().getAuthorizationServletConfig().isUseProxy()) {
            //forward to the proxy. If it succeeds there, set the rfc state to valid.
            try {
                ProxyUtils.getProxyAccessToken(getOA2SE(), transaction);
            } catch (Throwable throwable) {
                rollback(backup); // something blew up in the proxy. Let someone fix it and retry
                if (throwable instanceof OA2GeneralError) {
                    throw throwable;
                }

                if (throwable instanceof ServiceClientHTTPException) {
                    throw ProxyUtils.toOA2ATException((ServiceClientHTTPException) throwable, transaction);
                }
                throw new OA2ATException("server_error", throwable.getMessage(),
                        HttpStatus.SC_INTERNAL_SERVER_ERROR, transaction.getRequestState());
            }
            /*
            It is possible this will throw an exception at this point, since the proxy
            might (all the standard failure modes for retry, e.g. are in effect).
            */
        } else {
            // We allow for letting them try the request on the first try as soon
            // as they get their code.
            boolean throwSlowDown = false;

            if (rfc8628State.firstTry) {
                rfc8628State.firstTry = false; // used it up. No more first tries
                //    rfc8628State.interval = rfc8628State.interval + DEFAULT_WAIT;
            } else {
                if (rfc8628State.lastTry + rfc8628State.interval > now) {
                    throwSlowDown = true;
                }
            }
            rfc8628State.lastTry = now;
            transaction.setRFC8628State(rfc8628State);
            getTransactionStore().save(transaction);
            if (!rfc8628State.valid) {
                if (throwSlowDown) {
                    throw new OA2ATException("slow_down",
                            "slow down",
                            HttpStatus.SC_BAD_REQUEST,
                            transaction.getRequestState());

                }
                throw new OA2ATException("authorization_pending", "authorization pending",
                        HttpStatus.SC_BAD_REQUEST, transaction.getRequestState());
            }
        }


        // If we make it this far, we just turn the entire thing over to the standard access token flow
        transaction.setAuthGrantValid(false);
        getTransactionStore().save(transaction);

        IssuerTransactionState issuerTransactionState = getIssuerTransactionState(
                request,
                response,
                authorizationGrant,
                transaction,
                client,
                backup,
                true);
        try {
            // Fix https://github.com/ncsa/oa4mp/issues/164
            String verifier = request.getParameter(RFC7636Util.CODE_VERIFIER);
            checkCodeChallenge(transaction, client, verifier);
            doAT(issuerTransactionState, client);
        } catch (Throwable t) {
            rollback(backup);
            throw t;
        }
        debugger.trace(this, "returns from doAT");
        OA2SE oa2se = (OA2SE) OA4MPServlet.getServiceEnvironment();
        VirtualIssuer vo = oa2se.getVI(transaction.getClient().getIdentifier());
        if (vo == null) {
            debugger.trace(this, "no vi");
            ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setJsonWebKey((oa2se).getJsonWebKeys().getDefault());
        } else {
            debugger.trace(this, "has vi");
            ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        debugger.trace(this, "writing AT response");
        writeATResponse(response, issuerTransactionState);

    }

    private void checkSentScopes(HttpServletRequest request, HttpServletResponse response, OA2ServiceTransaction transaction) {
        String scope = getFirstParameterValue(request, OA2Constants.SCOPE);
        OA2Client oa2Client = OA2ClientUtils.resolvePrototypes(getOA2SE(), transaction.getOA2Client());
        if (!StringUtils.isTrivial(scope)) {
            // scope is optional, so only take notice if they send something
            TransactionState transactionState = new TransactionState(request, response, null, transaction, null);
            try {
                transaction.setScopes(ClientUtils.resolveScopes(transactionState, oa2Client, true));
            } catch (OA2RedirectableError redirectableError) {
                throw new OA2ATException(redirectableError.getError(),
                        redirectableError.getDescription(),
                        HttpStatus.SC_BAD_REQUEST,
                        redirectableError.getState());
            }
        } else {
            if (transaction.getScopes().isEmpty()) {
                // If there are no requested scopes any place, set the scopes to the
                // default for the client. This should be done here since this
                // is always assumed set henceforth.
                transaction.setScopes(oa2Client.getScopes());
            }
        }
    }
}
