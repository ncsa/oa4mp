package edu.uiuc.ncsa.oa2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ExtendedParameters;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptRuntimeEngineFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.TokenInfoRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.TokenInfoRecordMap;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2TStoreInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.UITokenUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientDebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.TransactionState;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.*;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.*;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.JWTRunner;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.JWTUtil2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.*;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.servlet.ServiceClientHTTPException;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.NONCE;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.STATE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  2:03 PM
 */
public class OA2ATServlet extends AbstractAccessTokenServlet2 {

    @Override
    public void destroy() {
        super.destroy();
        shutdownCleanup(AbstractAccessTokenServlet2.txRecordCleanup); // try to shutdown cleanly
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

        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        if (grantType.equals(RFC7523Constants.GRANT_TYPE_JWT_BEARER)) {
            // If the client is doing an RFC 7523 grant, then it must authorize accordingly.
            OA2Client oa2Client = OA2HeaderUtils.getAndVerifyRFC7523Client(request, (OA2SE) getServiceEnvironment());
            if (!oa2Client.isServiceClient()) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT, "client not authorized to do RFC7523 requests");
            }
            doRFC7523(request, response, oa2Client);
            return true;
        }
        OA2Client client = (OA2Client) getClient(request);
        // In all other cases, the client credentials must be sent.
        if (client == null) {
            warn("executeByGrant encountered a null client");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no such client");

        }
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
        debugger.trace(this, "starting execute by grant, grant = \"" + grantType + "\"");
        OA2Client resolvedClient = OA2ClientUtils.resolvePrototypes(oa2SE, client);
        if (!resolvedClient.isPublicClient()) {
            verifyClient(resolvedClient, request, true);
            //verifyClientSecret(resolvedClient, getClientSecret(request));
        }
        if (grantType.equals(RFC8693Constants.GRANT_TYPE_TOKEN_EXCHANGE)) {
            if (!oa2SE.isRfc8693Enabled()) {
                warn("Client " + client.getIdentifierString() + " requested a token exchange but token exchange is not enabled onthis server.");
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
        JSONObject jsonRequest = null;
        try {
            String raw = request.getParameter(RFC7523Constants.ASSERTION);
            if (StringUtils.isTrivial(raw)) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing json assertion");
            }
            if(client.hasJWKS()) {
                jsonRequest = JWTUtil2.verifyAndReadJWT(raw, client.getJWKS());
            }else{
                if(client.hasJWKSURI()){
                    jsonRequest = JWTUtil2.verifyAndReadJWT(raw, client.getJwksURI());
                }else{
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing JSON web key. Cannot verify signature."); // Not a JWT
                }
            }
        } catch (IllegalArgumentException iax) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid JWT:"); // Not a JWT

        } catch (Throwable t) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid json assertion:" + t.getMessage()); // Something is wrong with the JWT --
        }
        if (!jsonRequest.containsKey(OA2Claims.ISSUER)) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing issuer");
        }
        if (!client.getIdentifierString().equals(jsonRequest.getString(OA2Claims.ISSUER))) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "invalid issuer");
        }
        if (!jsonRequest.containsKey(OA2Claims.SUBJECT)) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "missing subject");
        }
        if (jsonRequest.getLong(OA2Claims.EXPIRATION) * 1000L < System.currentTimeMillis()) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "expired assertion token");
        }
        Collection<String> scopes;
        if (jsonRequest.containsKey(OA2Constants.SCOPE)) {
            Object ss = jsonRequest.get(OA2Constants.SCOPE);
            if (ss instanceof JSONArray) {
                scopes = (JSONArray) ss;
            } else {
                scopes = new ArrayList<>();
                scopes.add(ss.toString());
            }
        } else {
            scopes = new ArrayList<>();
        }
        String state = jsonRequest.containsKey(STATE) ? jsonRequest.getString(STATE) : null;
        String nonce = jsonRequest.containsKey(NONCE) ? jsonRequest.getString(NONCE) : null;

        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) getOA2SE().getTransactionStore().create();
        serviceTransaction.setRequestState(state);
        serviceTransaction.setNonce(nonce);
        serviceTransaction.setClient(client);
        serviceTransaction.setAuthTime(new Date()); // auth time is now.
        String user = jsonRequest.getString(OA2Claims.SUBJECT);
        if(client.getServiceClientUsers().contains("*")){
            serviceTransaction.setUsername(user);
        }else{
            if(client.getServiceClientUsers().contains(user)){
                serviceTransaction.setUsername(user);
            }else{
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "user \"" + user + "\" does not have permission");
            }
        }
        if (client.hasExtendedAttributeSupport()) {
            ExtendedParameters xp = new ExtendedParameters();
            // Take the parameters and parse them into configuration objects,
            JSONObject extAttr = xp.snoopParameters(jsonRequest);
            if (extAttr != null && !extAttr.isEmpty()) {
                serviceTransaction.setExtendedAttributes(extAttr);
            }
        }
        JSONObject claims = new JSONObject();
        claims.put(OA2Claims.SUBJECT, serviceTransaction.getUsername());
        serviceTransaction.setUserMetaData(claims); // set this so it exists for later.
        try {
            serviceTransaction.setScopes(ClientUtils.resolveScopes(request,
                    serviceTransaction,
                    client,
                    scopes,
                    true, false));
        } catch (OA2RedirectableError redirectableError) {
            throw new OA2ATException(OA2Errors.INVALID_SCOPE,
                    "unable to determine scopes",
                    HttpStatus.SC_BAD_REQUEST,
                    state, client);
        }
        if (jsonRequest.containsKey(OA2Constants.ACCESS_TOKEN_LIFETIME)) {
            String rawATLifetime = jsonRequest.getString(OA2Constants.ACCESS_TOKEN_LIFETIME);
            try {
                long at = ConfigUtil.getValueSecsOrMillis(rawATLifetime);
                //               long at = Long.parseLong(rawATLifetime);
                serviceTransaction.setRequestedATLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set request access token lifetime to \"" + rawATLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }
        }

        serviceTransaction.setAccessTokenLifetime(ClientUtils.computeATLifetime(serviceTransaction, client, getOA2SE()));
        if(jsonRequest.containsKey(OA2Constants.REFRESH_LIFETIME)){
            String rawRTLifetime = jsonRequest.getString(OA2Constants.REFRESH_LIFETIME);
            try {
                long at = ConfigUtil.getValueSecsOrMillis(rawRTLifetime);
                //               long at = Long.parseLong(rawATLifetime);
                serviceTransaction.setRequestedRTLifetime(at);
            } catch (Throwable t) {
                getServiceEnvironment().info("Could not set request refresh token lifetime to \"" + rawRTLifetime
                        + "\" for client " + client.getIdentifierString());
                // do nothing.
            }

        }
        if (client.isRTLifetimeEnabled()) {

            serviceTransaction.setRefreshTokenLifetime(ClientUtils.computeRefreshLifetime(serviceTransaction, client, getOA2SE()));
        } else {
            serviceTransaction.setRefreshTokenLifetime(0L);
        }
        try {
            String[] rawResource = extractArray(jsonRequest, RFC8693Constants.RESOURCE);
            String[] rawAudience = extractArray(jsonRequest, RFC8693Constants.AUDIENCE);
            OA2AuthorizedServletUtil.figureOutAudienceAndResource(serviceTransaction, rawResource, rawAudience);
        } catch (OA2GeneralError ge) {
            throw new OA2ATException(ge.getError(), ge.getDescription(), ge.getHttpStatus(), state, client);
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

        // Almost ready to rock and roll. Need the issuer transaction state, then do a standard AT
        // This, among other things, runs QDL scripts.
        IssuerTransactionState issuerTransactionState = new IssuerTransactionState(request, response, new HashMap<>(),
                serviceTransaction, new XMLMap(), atiResponse2);
        issuerTransactionState = doAT(issuerTransactionState, client);
        // Now, get the right signing key
        VirtualOrganization vo = getOA2SE().getVO(client.getIdentifier());
        JSONWebKey key = null;
        if (vo != null && vo.getJsonWebKeys() != null) {
            key = vo.getJsonWebKeys().get(vo.getDefaultKeyID());
        } else {
            key = getOA2SE().getJsonWebKeys().getDefault();
        }
        ATIResponse2 atResponse = (ATIResponse2) issuerTransactionState.getIssuerResponse();
        atResponse.setJsonWebKey(key);
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
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();

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
                if (adminClient.getVirtualOrganization() == null) {
                    jsonWebKeys = oa2SE.getJsonWebKeys();
                } else {
                    VirtualOrganization vo = (VirtualOrganization) oa2SE.getVOStore().get(adminClient.getVirtualOrganization());
                    if (vo == null) {
                        // Admin client is in a VO but no such VO is found. This implies an internal error
                        throw new NFWException("Virtual organization \"" + adminClient.getVirtualOrganization() + "\"not found.");
                    }
                    jsonWebKeys = vo.getJsonWebKeys();
                }
                JWTUtil.verifyAndReadJWT(token.getToken(), jsonWebKeys); // might throw an exception
            }
        } else {
            if (at.isJWT()) {
                JSONWebKeys jsonWebKeys;
                VirtualOrganization vo = getOA2SE().getVO(clientID);
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
        atResponse.setClaims(t.getUserMetaData());
        atResponse.write(response);
    }

    // Token exchange
    private void doRFC8693(OA2Client client,
                           HttpServletRequest request,
                           HttpServletResponse response) throws IOException {
        // https://tools.ietf.org/html/rfc8693

        String subjectToken = getFirstParameterValue(request, RFC8693Constants.SUBJECT_TOKEN);
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
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
        String requestedTokenType = getFirstParameterValue(request, RFC8693Constants.REQUESTED_TOKEN_TYPE);

        if (StringUtils.isTrivial(requestedTokenType)) {
            requestedTokenType = RFC8693Constants.ACCESS_TOKEN_TYPE;
        }
        debugger.trace(this, "requested token type set to " + requestedTokenType);
        // And now do the spec stuff for the actor token
        String actorToken = getFirstParameterValue(request, RFC8693Constants.ACTOR_TOKEN);
        String actorTokenType = getFirstParameterValue(request, RFC8693Constants.ACTOR_TOKEN_TYPE);
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
        OA2SE oa2se = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        String subjectTokenType = getFirstParameterValue(request, RFC8693Constants.SUBJECT_TOKEN_TYPE);
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
        List<String> scopes = convertToList(request, OA2Constants.SCOPE);
        /*
          There is an entire RFC now associated with the resource parameter:

          https://tools.ietf.org/html/rfc8707

          Argh!
         */
        List<String> audience = convertToList(request, RFC8693Constants.AUDIENCE);
        List<String> resources = convertToList(request, RFC8693Constants.RESOURCE);

        //CIL-974
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2se, client);
        debugger.trace(this, "got web keys, getting transaction from the client id in the request");

        switch (subjectTokenType) {
            case RFC8693Constants.ACCESS_TOKEN_TYPE:
                accessToken = OA2TokenUtils.getAT(subjectToken, oa2se, keys, debugger);
                t = ((OA2TStoreInterface) getTransactionStore()).get(accessToken, client.getIdentifier());
                break;
            case RFC8693Constants.REFRESH_TOKEN_TYPE:
                refreshToken = OA2TokenUtils.getRT(subjectToken, oa2se, keys, debugger);
                RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
                t = (OA2ServiceTransaction) rts.get(refreshToken, client.getIdentifier());
                break;
            case RFC8693Constants.ID_TOKEN_TYPE:
                throw new OA2ATException(OA2Errors.INVALID_GRANT, "ID token exchange not supported", t.getRequestState());
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
        unique identifiers. If there are for a flow with AG == A, then the new flow has
        AG A&eid=hash where the has is a hash of the ersatz client ID (ensuring that the identifier
        is unique and not too long to hit database limits for primary keys). Access tokens
        and refresh tokens, however, are NOT unique in the database
         */

        if (t == null) {
            debugger.trace(this, "transaction not found from credentials for client \""
                    + client.getIdentifierString() + "\", attempting to get transaction from the token itself");

            switch (subjectTokenType) {
                case RFC8693Constants.ACCESS_TOKEN_TYPE:
                    t = (OA2ServiceTransaction) getTransactionStore().get(accessToken);
                    break;
                case RFC8693Constants.REFRESH_TOKEN_TYPE:
                    RefreshTokenStore rts = (RefreshTokenStore) getTransactionStore();
                    try {
                        t = rts.get(refreshToken);
                    } catch (TransactionNotFoundException transactionNotFoundException) {
                        // fine. Look in the TX store later.
                    }
                    break;
            }
            if (t != null) {

                debugger.trace(this, "transaction found, checking for ersatz client:" + t.summary());

                // found something under another client id. Check for substitution
                PermissionsStore<? extends Permission> pStore = getOA2SE().getPermissionStore();
                List<Identifier> adminIDS = pStore.getAdmins(client.getIdentifier());
                if (adminIDS.isEmpty()) {
                    // If the client is not managed, it should not be substituting for anything.
                    debugger.trace(this, "client is not managed, any place");
                    throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                            "no substitutions allowed for unmanaged clients",
                            HttpStatus.SC_UNAUTHORIZED, null, t.getClient());
                }
                if (1 < adminIDS.size()) {
                    // So if there is a client managed by multiple admins, we don't just switch
                    // virtual organizations in the middle. No hijacking allowed. This is possible to do, but generally
                    // admins do not share clients, so we'll flag it as an exception here and if this
                    // ever needs to change, this tells us it is not working.
                    debugger.trace(this, "multiple admins for client " + client.getIdentifierString());
                    throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                            "multiple administrators for a managed client is not allowed",
                            HttpStatus.SC_UNAUTHORIZED, null, t.getClient());
                }

                Permission p = pStore.getErsatzChain(adminIDS.get(0), t.getOA2Client().getIdentifier(), client.getIdentifier());

                if (p == null) {
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
                //Identifier id = t2.getIdentifier();
                //id = BasicIdentifier.newID(id.toString() + "&eid=" + DigestUtils.sha1Hex(client.getIdentifierString()));
                //t2.setIdentifier(id);
                // These must be unique to go into the store, but are immediately replaced below with a TX record.
                // All that matters is they exist and be different from anything else present.
                AuthorizationGrantImpl ag = (AuthorizationGrantImpl) getTF2().getAuthorizationGrant();
                AccessTokenImpl at = getTF2().getAccessToken();
                RefreshTokenImpl rt = getTF2().getRefreshToken();
                t2.setIdentifier(BasicIdentifier.newID(ag.getJti()));
                t2.setAuthorizationGrant(ag); // This is used as the !key in the store.
                t2.setAccessToken(at);
                t2.setRefreshToken(rt);
                // Need inheritance from provisioning client,
                try {
                    client = createErsatz(t.getOA2Client().getIdentifier(), client, p.getErsatzChain());
                } catch (UnknownClientException ucx) {
                    debugger.trace(this, "ersatz client has unknown provisioner in chain.");

                    throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                            ucx.getMessage(), HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            t.getRequestState(),
                            t.getClient());
                }
                t2.setProvisioningClientID(t.getOA2Client().getIdentifier()); // So we can find it later
                t2.setProvisioningAdminID(adminIDS.get(0));
                t2.setClient(client);
                t2.getUserMetaData().put(OA2Claims.AUDIENCE, client.getIdentifierString()); // so id token has right audience

                debugger = MyProxyDelegationServlet.createDebugger(client); // switch over to logging for the 𝕰𝖗s𝖆𝖙𝖟 client.
                getTransactionStore().save(t2);
                // rock on. A new transaction has been created for this and the flow from the original may now diverge.
                t = t2;
            }
        }


        if (t == null) {
            // if there is no such transaction found, then this is probably from a previous exchange. Go find it
            try {
                if (accessToken != null) {
                    t = OA2TokenUtils.getTransactionFromTX(oa2se, accessToken, debugger);
                }
                if (refreshToken != null) {
                    t = OA2TokenUtils.getTransactionFromTX(oa2se, refreshToken, debugger);
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
        if (client.isErsatzClient() && !client.isReadOnly()) {
            // Gotten this far and there is an ersatz client. Read only is a good as "has been resolved"
            debugger.trace(this, "resolving ersatz client");
            try {
                Permission p = getOA2SE().getPermissionStore().getErsatzChain(t.getProvisioningAdminID(), t.getProvisioningClientID(), client.getIdentifier());
                client = createErsatz(t.getProvisioningClientID(), client, p.getErsatzChain());
                debugger = MyProxyDelegationServlet.createDebugger(client);
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
        debugger.trace(this, "client is " + client);
        /*
           Earth shaking change is that we need to create a new token exchange record for each exchange since the tokens
           have a lifetime and lifecycle of their own. Once in the wild, people may come back to this
           service and swap them willy nilly.
         */
        XMLMap tBackup = GenericStoreUtils.toXML(getTransactionStore(), t);
        if (client.hasExtendedAttributeSupport()) {
                ExtendedParameters xp = new ExtendedParameters();
                // Take the parameters and parse them into configuration objects,
                JSONObject extAttr = xp.snoopParameters(request.getParameterMap());
                if (extAttr != null && !extAttr.isEmpty()) {
                    t.setExtendedAttributes(extAttr);
                }
            }
        // In practice exactly one of these is active at any given time
        TXRecord newIDTX = null;
        TXRecord newATTX = null;
        TXRecord newRTTX = null;
        TXRecord activeTX = null;
        switch (requestedTokenType) {
            case RFC8693Constants.ID_TOKEN_TYPE:
                newIDTX = (TXRecord) oa2se.getTxStore().create();
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
        RTI2 rtIssuer = new RTI2(getTF2(), MyProxyDelegationServlet.getServiceEnvironment().getServiceAddress());
        RTIResponse rtiResponse = (RTIResponse) rtIssuer.process(rtiRequest);
        debugger.trace(this, "rti response=" + rtiResponse);
        rtiResponse.setSignToken(client.isSignTokens());
        // These are the claims that are returned in the RFC's required response. They have nothing to do
        // with id token claims, fyi.
        JSONObject rfcClaims = new JSONObject();

        debugger.trace(this, "requested token type = " + requestedTokenType);
        switch (requestedTokenType) {
            case RFC8693Constants.ACCESS_TOKEN_TYPE:
                // do NOT reset the refresh token
                // All the machinery from here out gets the RT from the rtiResponse.

                rfcClaims.put(RFC8693Constants.ISSUED_TOKEN_TYPE, RFC8693Constants.ACCESS_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, RFC8693Constants.TOKEN_TYPE_BEARER); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                rfcClaims.put(OA2Constants.EXPIRES_IN, t.getAccessTokenLifetime() / 1000); // internal in ms., external in sec.
                activeTX.setLifetime(t.getAccessTokenLifetime());

                activeTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getAccessToken().getToken()));
          /*      if(provisionErsatz){
                     ersatzTXR.setLifetime(t.getRefreshTokenLifetime());
                     ersatzTXR.setIdentifier(BasicIdentifier.newID(rtiResponse.getAccessToken().getToken()));
                }*/
                rtiResponse.setRefreshToken(null); // no refresh token should get processed except in Ersatz case.
                debugger.trace(this, "Processed access token return type");
                break;
            case RFC8693Constants.REFRESH_TOKEN_TYPE:
                rfcClaims.put(RFC8693Constants.ISSUED_TOKEN_TYPE, RFC8693Constants.REFRESH_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, RFC8693Constants.TOKEN_TYPE_N_A); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                rfcClaims.put(OA2Constants.EXPIRES_IN, t.getRefreshTokenLifetime() / 1000); // internal in ms., external in sec.
                activeTX.setLifetime(t.getRefreshTokenLifetime());
                activeTX.setIdentifier(BasicIdentifier.newID(rtiResponse.getRefreshToken().getToken()));
                debugger.trace(this, "Processed refresh token return type");
          /*      if(provisionErsatz){
                    ersatzTXR.setIdentifier(BasicIdentifier.newID(rtiResponse.getAccessToken().getToken()));
                    ersatzTXR.setLifetime(t.getAccessTokenLifetime());
                }*/
                break;
            case RFC8693Constants.ID_TOKEN_TYPE:
                rfcClaims.put(RFC8693Constants.ISSUED_TOKEN_TYPE, RFC8693Constants.ID_TOKEN_TYPE); // Required. This is the type of token issued (mostly access tokens). Must be as per TX spec.
                rfcClaims.put(OA2Constants.TOKEN_TYPE, RFC8693Constants.TOKEN_TYPE_N_A); // Required. This is how the issued token can be used, mostly. BY RFC 6750 spec.
                JSONObject md = t.getUserMetaData();
                if (md.containsKey(OA2Claims.EXPIRATION) && md.containsKey(OA2Claims.ISSUED_AT)) {
                    long exp = md.getLong(OA2Claims.EXPIRATION) - md.getLong(OA2Claims.ISSUED_AT);
                    rfcClaims.put(OA2Constants.EXPIRES_IN, exp / 1000); // internal in ms., external in sec.
                    activeTX.setLifetime(exp); // in ms.
                }
                activeTX.setIdentifier(BasicIdentifier.newID(md.getString(OA2Claims.JWT_ID)));
                debugger.trace(this, "Processed id token return type");
                break;
            default:
                throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                        "unknown requested token type",
                        t.getRequestState());
        }
        activeTX.setExpiresAt(activeTX.getIssuedAt() + activeTX.getLifetime());
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2se, t, activeTX, t.getOA2Client().getConfig()));
        try {
            OA2ClientUtils.setupHandlers(jwtRunner, oa2se, t, client, newIDTX, newATTX, newRTTX, request);
            // NOTE WELL that the next two lines are where our identifiers are used to create JWTs (like SciTokens)
            // so if this is not done, the wrong token type will be returned.
            jwtRunner.doTokenExchange();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2se, throwable, debugger, t, tBackup, activeTX);
        }

        setupTokens(client, rtiResponse, oa2se, t, jwtRunner, true, debugger);
        debugger.trace(this, "rtiResponse after token setup:" + rtiResponse);
        switch (requestedTokenType) {
            case RFC8693Constants.ACCESS_TOKEN_TYPE:
                if (((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().getToken()); // Required.
                    newATTX.setStoredToken(rtiResponse.getAccessToken().getToken());

                } else {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getAccessToken().encodeToken()); // Required.
                }
                // create scope string  Remember that these may have been changed by a script,
                // so here is the right place to set it.
                rfcClaims.put(OA2Constants.SCOPE, listToString(newATTX.getScopes()));
                break;
            case RFC8693Constants.REFRESH_TOKEN_TYPE:
                if (rtiResponse.getRefreshToken().isJWT()) {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().getToken()); // Required
                    rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().getToken()); // Optional
                    newRTTX.setStoredToken(rtiResponse.getRefreshToken().getToken());
                } else {
                    rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Required
                    rfcClaims.put(OA2Constants.REFRESH_TOKEN, rtiResponse.getRefreshToken().encodeToken()); // Optional
                }
                break;
            case RFC8693Constants.ID_TOKEN_TYPE:
                rfcClaims.put(OA2Constants.ACCESS_TOKEN, rtiResponse.getClaims());
        }
        debugger.trace(this, "rfc claims returned:" + rfcClaims.toString(1));
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


        if (newIDTX != null) {
            newIDTX.setValid(true);
            oa2se.getTxStore().save(newIDTX);
        }
        if (newATTX != null) {
            newATTX.setValid(true);
            oa2se.getTxStore().save(newATTX);
        }
        if (newRTTX != null) {
            newRTTX.setValid(true);
            oa2se.getTxStore().save(newRTTX);
        }
        getTransactionStore().save(t);
        PrintWriter osw = response.getWriter();
        rfcClaims.write(osw);
        osw.flush();
        osw.close();


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
        List<Identifier> prototypes = new ArrayList<>();
        if (ersatzClient.isExtendsProvisioners()) {
            prototypes.add(provisioningClientID); // this is normally not in the chain
            prototypes.addAll(ersatzChain.subList(0, ersatzChain.size() - 1)); // last element is ersatzClient, so skip
            prototypes.addAll(ersatzClient.getPrototypes());
            ersatzClient.setPrototypes(prototypes);
        }
        return OA2ClientUtils.resolvePrototypes(getOA2SE(), ersatzClient);
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
        warn("Error: grant type +\"" + grantType + "\" was not recognized. Request rejected.");
        throw new OA2ATException(OA2Errors.REQUEST_NOT_SUPPORTED,
                "unsupported grant type \"" + grantType + "\"");
    }

    @Override
    protected ATRequest getATRequest(HttpServletRequest request, ServiceTransaction transaction,
                                     OA2Client client) {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;
        // Set these in the transaction then send it along.
        t.setAccessTokenLifetime(ClientUtils.computeATLifetime(t, client, (OA2SE) MyProxyDelegationServlet.getServiceEnvironment()));
        if (client.isRTLifetimeEnabled()) {
            if (((OA2SE) MyProxyDelegationServlet.getServiceEnvironment()).isRefreshTokenEnabled()) {
                t.setRefreshTokenLifetime(ClientUtils.computeRefreshLifetime(t, client, (OA2SE) MyProxyDelegationServlet.getServiceEnvironment()));
            }
        } else {
            t.setRefreshTokenLifetime(0L);
            t.setMaxRTLifetime(0L);
        }

        return new ATRequest(request, transaction);
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
        return (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
    }

    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = doDelegation(client, request, response);
        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) state.getTransaction();

        if (serviceTransaction.hasCodeChallenge()) {
            String verifier = request.getParameter(RFC7636Util.CODE_VERIFIER);
            if (StringUtils.isTrivial(verifier)) {
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "missing verifier, access denied",
                        serviceTransaction.getRequestState());
            }
            String codeChallenge = RFC7636Util.createChallenge(verifier, serviceTransaction.getCodeChallengeMethod());
            if (StringUtils.isTrivial(codeChallenge)) {
                // CIL-1307
                MyProxyDelegationServlet.createDebugger(client).trace(this, "Missing verifier, PKCE (RFC 7636) failed");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "bad or missing code challenge, access denied",
                        serviceTransaction.getRequestState());
            }
            if (!codeChallenge.equals(serviceTransaction.getCodeChallenge())) {
                // CIL-1307
                MyProxyDelegationServlet.createDebugger(client).trace(this, "missing code challenge, PKCE (RFC 7636) failed");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "code challenge failed, access denied",
                        serviceTransaction.getRequestState());
            }
        } else {
            if (getOA2SE().isRfc7636Required() && client.isPublicClient()) {
                MyProxyDelegationServlet.createDebugger(client).trace(this, "public client failed to send required code challenge, PKCE (RFC 7636) failed.");
                throw new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "code challenge failed, access denied",
                        serviceTransaction.getRequestState());
            }
        }
        return doAT(state, client);
    }

    protected IssuerTransactionState doAT(IssuerTransactionState state, OA2Client client) throws Throwable {
        // Grants are checked in the doIt method
        XMLMap tBackup = state.getBackup(); // stash it here.
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();

        atResponse.setSignToken(client.isSignTokens());
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();

        OA2ServiceTransaction st2 = (OA2ServiceTransaction) state.getTransaction();
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(st2.getClient());
        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(st2);
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
        List<String> audience = convertToList(state.getRequest(), RFC8693Constants.AUDIENCE);
        List<String> resources = convertToList(state.getRequest(), RFC8693Constants.RESOURCE);
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

            atTX.setTokenType(RFC8693Constants.ACCESS_TOKEN_TYPE); // Ensure that handlers can recognize this for access tokens.
            atTX.setIdentifier(BasicIdentifier.newID(atResponse.getAccessToken().getToken()));
        }
        /* *************** */

        if (client.isRTLifetimeEnabled()) {
            st2.setRefreshToken(atResponse.getRefreshToken()); // ditto. Might be null.
        } else {
            st2.setRefreshToken(null);
            st2.setRefreshTokenLifetime(0L);
        }
        JWTRunner jwtRunner = new JWTRunner(st2, ScriptRuntimeEngineFactory.createRTE(oa2SE, st2, atTX, st2.getOA2Client().getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, st2, client, null, atTX, rtTX, state.getRequest());
        if (state.isRfc8628() || st2.getAuthorizationGrant().getVersion() == null || st2.getAuthorizationGrant().getVersion().equals(Identifiers.VERSION_1_0_TAG)) {
            // Handlers have not been initialized yet. Either because of old tokens or rfc 8628 (so no tokens).
            jwtRunner.initializeHandlers();
        }
        try {
            jwtRunner.doTokenClaims();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2SE, throwable, createDebugger(st2.getClient()), st2, tBackup);
        }

        if (!client.isRTLifetimeEnabled()) {
            atResponse.setRefreshToken(null);
        }
        setupTokens(client, atResponse, oa2SE, st2, jwtRunner, debugger);

        AccessTokenImpl tempAT = (AccessTokenImpl) atResponse.getAccessToken();
        if (tempAT.isJWT()) {
            st2.setATJWT(tempAT.getToken());
        }
        RefreshTokenImpl tempRT = (RefreshTokenImpl) atResponse.getRefreshToken();
        if (tempRT != null && tempRT.isJWT()) {
            st2.setRTJWT(tempRT.getToken());
        }
        debugger.trace(this, "got access token for transaction=" + st2.summary());
        // only do this before last save, so if the whole thing bombs, they can try again
        st2.setAuthGrantValid(false);
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
                             JWTRunner jwtRunner, MetaDebugUtil debugger) {
        setupTokens(client, tokenResponse, oa2SE, st2, jwtRunner, false, debugger);
    }

    /**
     * Takes the newly modified access and refresh tokens after all scripts are run
     * and updates the transaction so that whatever the script did is not stored in the system.
     *
     * @param client
     * @param tokenResponse
     * @param oa2SE
     * @param st2
     * @param jwtRunner
     * @param isTokenExchange
     */
    private void setupTokens(OA2Client client,
                             IDTokenResponse tokenResponse,
                             OA2SE oa2SE,
                             OA2ServiceTransaction st2,
                             JWTRunner jwtRunner,
                             boolean isTokenExchange,
                             MetaDebugUtil debugger
    ) {
        if (debugger == null) {
            debugger = MyProxyDelegationServlet.createDebugger(client);
        }
        VirtualOrganization vo = oa2SE.getVO(client.getIdentifier());
        JSONWebKey key = null;
        if (vo != null && vo.getJsonWebKeys() != null) {
            key = vo.getJsonWebKeys().get(vo.getDefaultKeyID());
        } else {
            key = oa2SE.getJsonWebKeys().getDefault();
        }
        if (jwtRunner.hasATHandler()) {
            AccessToken newAT = jwtRunner.getAccessTokenHandler().getSignedAT(key);
            debugger.trace(this, "jwt has at handler: at=" + newAT + ", for claims " + st2.getATData().toString(2));
            tokenResponse.setAccessToken(newAT);
            debugger.trace(this, "Returned AT from handler:" + newAT + ", for claims " + st2.getATData().toString(2));
        } else {
            debugger.trace(this, "NO ATHandler in jwtRunner");

        }
        tokenResponse.setClaims(st2.getUserMetaData());
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
            if (!isTokenExchange) {
                st2.setRefreshToken(rt);
                st2.setRefreshTokenValid(true);
            }
            if (jwtRunner.hasRTHandler()) {
                RefreshTokenImpl newRT = (RefreshTokenImpl) jwtRunner.getRefreshTokenHandler().getSignedRT(null); // unsigned, for now
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
            JSONObject jsonObject = JWTUtil2.verifyAndReadJWT(refreshToken.getToken(), ((OA2SE) MyProxyDelegationServlet.getServiceEnvironment()).getJsonWebKeys());
            if (jsonObject.containsKey(OA2Claims.JWT_ID)) {
                refreshToken = new RefreshTokenImpl(URI.create(jsonObject.getString(OA2Claims.JWT_ID)));
            } else {
                throw new OA2ATException(OA2Errors.INVALID_GRANT, "refresh token is a JWT, but has no " + OA2Claims.JWT_ID + " claim.");
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
        return (OA2TokenForge) MyProxyDelegationServlet.getServiceEnvironment().getTokenForge();
    }

    protected TransactionState doRefresh(OA2Client client, HttpServletRequest request, HttpServletResponse response) throws Throwable {
        // Grants are checked in the doIt method
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
        printAllParameters(request, debugger);
        String rawRefreshToken = request.getParameter(OA2Constants.REFRESH_TOKEN);
        if (client == null) {
            throw new OA2ATException(OA2Errors.INVALID_REQUEST, "Could not find the client associated with refresh token \"" + rawRefreshToken + "\"");
        }
        debugger.trace(this, "starting token refresh at " + (new Date()));
        // Check if it's a token or JWT
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        //CIL-974:
        JSONWebKeys keys = OA2TokenUtils.getKeys(oa2SE, client);
        RefreshTokenImpl oldRT;
        boolean tokenVersion1 = false;
        try {
            oldRT = OA2TokenUtils.getRT(rawRefreshToken, oa2SE, keys, debugger);
        } catch (OA2ATException oa2ATException) {
            info(oa2ATException.getError() + " in refresh for client " + client.getIdentifierString());
            throw oa2ATException;
        }
        OA2ServiceTransaction t = null;
        try {
            // Fix for CIL-882
            t = getByRT(oldRT);
            if (!t.getClient().getIdentifier().equals(client.getIdentifier())) {
                debugger.trace(this, "transaction lists client id \"" + t.getClient().getIdentifierString()
                        + "\", but the client in the request is \"" + client.getIdentifierString() + "\". Request rejected.");
                throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                        "wrong client",
                        HttpStatus.SC_BAD_REQUEST, null);

            }
        } catch (TransactionNotFoundException e) {
            t = OA2TokenUtils.getTransactionFromTX(oa2SE, oldRT, debugger);
            if (t == null) {
                String message = "The refresh token \"" + oldRT.getToken() + "\" for client " + client.getIdentifierString() + " is not expired, but also was not found.";
                debugger.info(this, message);
                throw new OA2ATException(OA2Errors.INVALID_TOKEN, "The token \"" + oldRT.getToken() + "\" could not be associated with a pending flow",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
        }
        XMLMap backup = GenericStoreUtils.toXML(getTransactionStore(), t);
        if (debugger instanceof ClientDebugUtil) {
            ((ClientDebugUtil) debugger).setTransaction(t);
        }
        if (tokenVersion1) {
            // Can't fix it until we have the right transaction.
            t.setRefreshTokenLifetime(ClientUtils.computeRefreshLifetime(t, client, oa2SE));
            t.setAccessTokenLifetime(ClientUtils.computeATLifetime(t, client, oa2SE));
        }

        if (t == null || !t.isRefreshTokenValid()) {
            debugger.trace(this, "Missing refresh token.");
            throw new OA2ATException(OA2Errors.INVALID_REQUEST,
                    "The refresh token is no longer valid.",
                    t.getRequestState());
        }
        if (client.hasExtendedAttributeSupport()) {
                ExtendedParameters xp = new ExtendedParameters();
                // Take the parameters and parse them into configuration objects,
                JSONObject extAttr = xp.snoopParameters(request.getParameterMap());
                if (extAttr != null && !extAttr.isEmpty()) {
                    t.setExtendedAttributes(extAttr);
                }
            }
        AccessTokenImpl at = (AccessTokenImpl) t.getAccessToken();
        debugger.trace(this, "old access token = " + at.getToken());
        List<String> scopes = convertToList(request, OA2Constants.SCOPE);
        List<String> audience = convertToList(request, RFC8693Constants.AUDIENCE);
        List<URI> resources = convertToURIList(request, RFC8693Constants.RESOURCE);


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
        RTIRequest rtiRequest = new RTIRequest(request, t, at, oa2SE.isOIDCEnabled());
        RTI2 rtIssuer = new RTI2(getTF2(), MyProxyDelegationServlet.getServiceEnvironment().getServiceAddress());

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
        txAT.setTokenType(RFC8693Constants.ACCESS_TOKEN_TYPE);
        txAT.setParentID(t.getIdentifier());
        txAT.setIdentifier(BasicIdentifier.newID(t.getAccessToken().getToken()));
        txAT.setExpiresAt(t.getAccessToken().getIssuedAt() + t.getAccessTokenLifetime());

        TXRecord txRT = (TXRecord) oa2SE.getTxStore().create();
        txRT.setTokenType(RFC8693Constants.REFRESH_TOKEN_TYPE);
        txRT.setParentID(t.getIdentifier());
        txRT.setIdentifier(BasicIdentifier.newID(t.getRefreshToken().getToken()));
        if (0 <= oa2SE.getRtGracePeriod()) {
            // If this is non-negative, then it has been configured. Not configured = let everything expire normally.
            txRT.setExpiresAt(System.currentTimeMillis() + oa2SE.getRtGracePeriod());
            txRT.setValid(0 != oa2SE.getRtGracePeriod()); // Valid if non-zero
        } else {
            RefreshTokenImpl rt = (RefreshTokenImpl) t.getRefreshToken();
            txRT.setExpiresAt(rt.getIssuedAt() + t.getRefreshTokenLifetime()); // use what it has.
        }
        // Make sure everything that needs it is updated.
        t.setAccessToken(rtiResponse.getAccessToken());
        t.getATData().put(OA2Claims.JWT_ID, rtiResponse.getAccessToken().getToken());
        t.setRefreshToken(rtiResponse.getRefreshToken());
        t.getRTData().put(OA2Claims.JWT_ID, rtiResponse.getRefreshToken().getToken());

        if (!scopes.isEmpty() || !audience.isEmpty() || !resources.isEmpty()) {
            txAT.setScopes(scopes);
            txAT.setAudience(audience);
            txAT.setResource(resources);
        }
        getOA2SE().getTxStore().save(txAT);
        getOA2SE().getTxStore().save(txRT);

//        getTransactionStore().save(t); // make sure all components can find this directly
        debugger.trace(this, "set new access token = " + rtiResponse.getAccessToken().getToken());

        // JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, txAT, t.getOA2Client().getConfig()));
        // OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, t, client, txAT, request);
        JWTRunner jwtRunner = new JWTRunner(t, ScriptRuntimeEngineFactory.createRTE(oa2SE, t, txAT, t.getOA2Client().getConfig()));
        OA2ClientUtils.setupHandlers(jwtRunner, oa2SE, t, client, request);

        try {
            jwtRunner.doRefreshClaims();
        } catch (Throwable throwable) {
            OA2ServletUtils.handleScriptEngineException(this, oa2SE, throwable, createDebugger(t.getClient()), t, backup, txAT);
        }
        setupTokens(client, rtiResponse, oa2SE, t, jwtRunner, debugger);

        debugger.trace(this, "finished processing claims.");

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
        VirtualOrganization vo = oa2SE.getVO(client.getIdentifier());

        if (vo == null) {
            rtiResponse.setJsonWebKey(oa2SE.getJsonWebKeys().getDefault());
        } else {
            rtiResponse.setJsonWebKey(vo.getJsonWebKeys().get(vo.getDefaultKeyID()));
        }
        rtiResponse.setClaims(t.getUserMetaData());
        // In refresh, both the access token and refresh token are replaced in the transaction,
        // and a new TXRecord pointing to the AT is made. If these are JWTs, stash them for use later
        // when getting token_info. Cannot do that until all other processing is done.
        // CIL-1268 moving this here fixed that.

        if (client.isRTLifetimeEnabled() && oa2SE.isRefreshTokenEnabled()) {
            t.setRefreshToken(rtiResponse.getRefreshToken());
            if (rtiResponse.getRefreshToken().isJWT()) {
                t.setRTJWT(rtiResponse.getRefreshToken().getToken());
            }
        } else {
            rtiResponse.setRefreshToken(null);
        }
        if (((AccessTokenImpl) rtiResponse.getAccessToken()).isJWT()) {
            t.setATJWT(rtiResponse.getAccessToken().getToken());
            txAT.setStoredToken(rtiResponse.getAccessToken().getToken());
        }

        getTransactionStore().save(t);
        oa2SE.getTxStore().save(txAT);
        oa2SE.getTxStore().save(txRT);
        debugger.trace(this, "transaction saved for " + t.getIdentifierString());

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
    }

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
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();

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

        OA2ServiceTransaction transaction = (OA2ServiceTransaction) MyProxyDelegationServlet.getServiceEnvironment().getTransactionStore().get(ag);
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(transaction.getOA2Client());
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
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
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
        if (client.hasExtendedAttributeSupport()) {
                ExtendedParameters xp = new ExtendedParameters();
                // Take the parameters and parse them into configuration objects,
                JSONObject extAttr = xp.snoopParameters(request.getParameterMap());
                if (extAttr != null && !extAttr.isEmpty()) {
                    transaction.setExtendedAttributes(extAttr);
                }
            }
        // Logic is simple. If proxy, farm it out to the proxy and it works or doesn't.
        // otherwise, manage all the state for retries.
        if (getOA2SE().getAuthorizationServletConfig().isUseProxy()) {
            //forward to the proxy. If it succeeds there, set the rfc state to valid.
            try {
                ProxyUtils.doRFC8628AT(getOA2SE(), transaction);
            } catch (Throwable throwable) {
                rollback(backup); // something blew up in the proxy. Let someone fix it and retry
                if (throwable instanceof OA2GeneralError) {
                    throw throwable;
                }

                if (throwable instanceof ServiceClientHTTPException) {
                    throw ProxyUtils.toOA2X((ServiceClientHTTPException) throwable, transaction);
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
            doAT(issuerTransactionState, client);
        } catch (Throwable t) {
            rollback(backup);
            throw t;
        }
        debugger.trace(this, "returns from doAT");
        OA2SE oa2se = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        VirtualOrganization vo = oa2se.getVO(transaction.getClient().getIdentifier());
        if (vo == null) {
            debugger.trace(this, "no vo");
            ((ATIResponse2) issuerTransactionState.getIssuerResponse()).setJsonWebKey((oa2se).getJsonWebKeys().getDefault());
        } else {
            debugger.trace(this, "has vo");
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
