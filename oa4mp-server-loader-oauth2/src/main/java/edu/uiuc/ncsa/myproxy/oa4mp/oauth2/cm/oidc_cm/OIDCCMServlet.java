package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.AddClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.RemoveClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.HeaderUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.EnvServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.ClientConfigurationUtil;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Note that in all of these calls, the assumption is that an admin client has been requested and
 * approved out of band. The identifier and secret of that are used to make the bearer token that
 * allows access to the calls in this API. This implements both RFC 7591 and part of RFC 7592.
 * Mostly we do not allow the setting of client secrets via tha API and since we do not store them
 * (only a hash of them) we cannot return them. If a secret is lost, the only option is to register a new
 * client. RFC 7592 is not intended to become a specification since ther eis too much variance in how
 * this can operate.
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/18 at  10:04 AM
 */
public class OIDCCMServlet extends EnvServlet {
    @Override
    public void storeUpdates() throws IOException, SQLException {
        if (storeUpdatesDone) return; // run this once
        storeUpdatesDone = true;
        processStoreCheck(getOA2SE().getAdminClientStore());
        processStoreCheck(getOA2SE().getPermissionStore());
    }

    protected OA2SE getOA2SE() {
        return (OA2SE) getEnvironment();
    }

    /**
     * Return information about the client. Note that we do not return the client secret in this call,
     * since among other reasons, we do not have it.
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @throws ServletException
     * @throws IOException
     */
    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        printAllParameters(httpServletRequest);
        if (doPing(httpServletRequest, httpServletResponse)) return;
        if (!getOA2SE().getCmConfigs().hasRFC7591Config()) {
            throw new IllegalAccessError("Error: RFC 7591 not supported on this server. Request rejected.");
        }

        try {
            AdminClient adminClient = getAndCheckAdminClient(httpServletRequest);
            String rawID = getFirstParameterValue(httpServletRequest, OA2Constants.CLIENT_ID);
            if (rawID == null || rawID.isEmpty()) {
                throw new GeneralException("Missing client id. Cannot process request");
            }
            Identifier id = BasicIdentifier.newID(rawID);
            OA2Client client = (OA2Client) getOA2SE().getClientStore().get(id);
            if (client == null) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "no such client",
                        HttpStatus.SC_BAD_REQUEST);
            }
            JSONObject json = toJSONObject(client);
            writeOK(httpServletResponse, json); //send it back with an ok.
        } catch (Throwable t) {
            handleException(t, httpServletRequest, httpServletResponse);
        }
    }

    protected JSONObject toJSONObject(OA2Client client) {
        JSONObject json = new JSONObject();
        String registrationURI = getOA2SE().getCmConfigs().getRFC7591Config().uri.toString();
        // Next, we have to construct the registration URI by adding in the client ID.
        // Spec says we can add parameters here, but not elsewhere.
        json.put(OIDCCMConstants.REGISTRATION_CLIENT_URI, registrationURI + "?" + OA2Constants.CLIENT_ID + "=" + client.getIdentifierString());
        json.put(OA2Constants.CLIENT_ID, client.getIdentifierString());
        json.put(OIDCCMConstants.CLIENT_NAME, client.getName());
        JSONArray cbs = new JSONArray();
        cbs.addAll(client.getCallbackURIs());
        json.put(OIDCCMConstants.REDIRECT_URIS, cbs);
        JSONArray grants = new JSONArray();
        grants.add(OA2Constants.AUTHORIZATION_CODE_VALUE);
        if (client.isRTLifetimeEnabled()) {
            grants.add(OA2Constants.REFRESH_TOKEN);
        }

        json.put(OIDCCMConstants.GRANT_TYPES, grants);
        JSONArray scopes = new JSONArray();
        scopes.addAll(client.getScopes());
        json.put(OA2Constants.SCOPE, scopes);
        json.put(OIDCCMConstants.CLIENT_URI, client.getHomeUri());
        json.put(OA2Constants.ERROR_URI, client.getErrorUri());
        // Note that a contact email is something specific to OA4MP and does not occur in
        // either RFC 7591 or 7592.
        json.put("email", client.getEmail());
        // This is in seconds since the epoch
        json.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, client.getCreationTS().getTime() / 1000);
        json.putAll(ClientConfigurationUtil.getExtraAttributes(client.getConfig()));
        return json;
    }


    /**
     * Remove the given client in toto.
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        printAllParameters(req);
        if (!getOA2SE().getCmConfigs().hasRFC7592Config()) {
            throw new IllegalAccessError("Error: RFC 7592 not supported on this server. Request rejected.");
        }

        try {
            AdminClient adminClient = getAndCheckAdminClient(req);
            String rawID = req.getParameter(OA2Constants.CLIENT_ID);
            if(rawID == null || rawID.isEmpty()){
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing client id", HttpStatus.SC_BAD_REQUEST);
            }
            OA2Client client = (OA2Client) getOA2SE().getClientStore().get(BasicIdentifier.newID(rawID));
            if(client == null){
                // Then this client does not exist on this server. Spec. says this is all fine and good
                resp.setStatus(HttpStatus.SC_NO_CONTENT);
                return;
            }
            checkAdminPermission(adminClient, client);

            // remove it from the store, then remove it from the approvals.
            // only admin clients can delete a client.
            getOA2SE().getClientApprovalStore().remove(client.getIdentifier());
            getOA2SE().getClientStore().remove(client.getIdentifier());
            // That removes it from storage, now remove it from the permission list for this admin client.
            RemoveClientRequest removeClientRequest = new RemoveClientRequest(adminClient, client);
            getPermissionServer().removeClient(removeClientRequest);
            resp.setStatus(HttpStatus.SC_NO_CONTENT); // no content is as per spec
            return;
        } catch (Throwable t) {
            handleException(t, req, resp);
        }
    }

    /**
     * Checks that this client exists on the system and that if it exists, the admin client actually
     * owns it.
     * @param adminClient
     * @param client
     */
    protected void checkAdminPermission(AdminClient adminClient, OA2Client client){
        if(client == null){
                 throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                         "unknown client",
                         HttpStatus.SC_UNAUTHORIZED // as per spec
                 );
             }
             // now we check that this admin owns this client
             List<Identifier> clientList = getOA2SE().getPermissionStore().getClients(adminClient.getIdentifier());
             if(!clientList.contains(client.getIdentifier())){
                     throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                             "access denied",
                             HttpStatus.SC_FORBIDDEN // as per spec.
                     );
             }

    }
    /**
     * Update a client. Note that as per the specification, all values that are sent over-write existing
     * values and omitted values are taken to mean the stored value is unset.
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (!getOA2SE().getCmConfigs().hasRFC7592Config()) {
            throw new IllegalAccessError("Error: RFC 7592 not supported on this server. Request rejected.");
        }

        try {
            AdminClient adminClient = getAndCheckAdminClient(req);
            OA2Client client = getClient(req);
            checkAdminPermission(adminClient, client);

            JSON rawJSON = getPayload(req);

            DebugUtil.trace(this, rawJSON.toString());
            if (rawJSON.isArray()) {
                getMyLogger().info("Error: Got a JSON array rather than a request:" + rawJSON);
                throw new IllegalArgumentException("Error: incorrect argument. Not a valid JSON request");
            }
            JSONObject jsonRequest = (JSONObject) rawJSON;

            if(jsonRequest.size() == 0){
                // Playing nice here. If they upload an empty object, the net effect is going to be to zero out
                // everything for this client except the id. The assumption is they don't want to do that.
                getMyLogger().info("Error: Got an empty JSON object. Request rejected.");
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "invalid request", HttpStatus.SC_BAD_REQUEST);
            }
            //have to check that certain key/values are excluded from the update.
            if(jsonRequest.containsKey(OIDCCMConstants.REGISTRATION_ACCESS_TOKEN) ||
            jsonRequest.containsKey(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT) ||
            jsonRequest.containsKey(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT) ||
            jsonRequest.containsKey(OIDCCMConstants.CLIENT_ID_ISSUED_AT)){
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "invalid parameter",
                        HttpStatus.SC_BAD_REQUEST);
            }
            if (jsonRequest.containsKey(OA2Constants.SCOPE)) {
                // the only thing that we are concerned with is is client is attempting to increase their
                // scopes. The are permitted to reduce them.
                boolean rejectRequest = false;
                JSONArray newScopes = jsonRequest.getJSONArray(OA2Constants.SCOPE);
                Collection<String> oldScopes = client.getScopes();
                if (oldScopes.size() < newScopes.size()) {
                    rejectRequest = true;
                } else {
                    for (Object x : newScopes) {
                        String scope = x.toString();
                        if (!oldScopes.contains(scope)) {
                            // then this is not in the list, request is rejected
                            rejectRequest = true;
                            break;
                        }
                    }
                }
                if (rejectRequest) {
                    throw new OA2GeneralError(OA2Errors.INVALID_SCOPE,
                            "invalid scope",
                            HttpStatus.SC_FORBIDDEN // as per spec, section RFC 7592 section 2.2
                    );
                }
            }
                // so we create a new client, set the secret and id, then update that. This way if
                // this fails we can just back out.
                OA2Client newClient = (OA2Client) getOA2SE().getClientStore().create();
                newClient.setIdentifier(client.getIdentifier());
                newClient.setSecret(client.getSecret());
                newClient.setConfig(client.getConfig());
                try {
                    newClient = updateClient(newClient, jsonRequest, resp);
                    getOA2SE().getClientStore().save(newClient);

                } catch (Throwable t) {
                    // back out of it
                    warn("Error attempting to update client \"" + client.getIdentifierString() + "\". " +
                            "Message = \"" + t.getMessage() + "\". Request is rejected");
                   // resp.setStatus(HttpStatus.SC_BAD_REQUEST);
                    handleException(t,req,resp);
                }
        } catch (Throwable t) {
            handleException(t, req, resp);
        }
    }

    @Override
    public void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        if (!getOA2SE().getCmConfigs().hasRFC7591Config()) {
            throw new IllegalAccessError("Error: RFC 7591 not supported on this server. Request rejected.");
        }
        try {
            // The super class rejects anything that does not have an encoding type of
            // application/x-www-form-urlencoded
            // We want this servlet to understand only application/json, so we
            // test for that instead.

            //   printAllParameters(httpServletRequest);
            if (doPing(httpServletRequest, httpServletResponse)) return;
            System.err.println("ENCODING is of type " + httpServletRequest.getContentType());
            // TODO Probably should parse the encoding type. 'application/json; charset=UTF-8' would be standard.
            if (!httpServletRequest.getContentType().contains("application/json")) {
                httpServletResponse.setStatus(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE);
                throw new ServletException("Error: Unsupported encoding of \"" + httpServletRequest.getContentType() + "\" for body of POST. Request rejected.");
            }
            // delegates to the doIt method.
            doIt(httpServletRequest, httpServletResponse);
        } catch (Throwable t) {
            handleException(t, httpServletRequest, httpServletResponse);
        }
    }

    /**
     * We want to be able to manage the permissions associated with a standard client and an admin client.
     *
     * @return
     */
    public PermissionServer getPermissionServer() {
        if (permissionServer == null) {
            permissionServer = new PermissionServer(getOA2SE());
        }
        return permissionServer;
    }

    /**
     * Pulls the id and secret from the header then verifies the secret and if it passes,
     * returns the client.
     * @param request
     * @return
     * @throws Throwable
     */
    protected AdminClient getAndCheckAdminClient(HttpServletRequest request) throws Throwable {
        String[] credentials = HeaderUtils.getCredentialsFromHeaders(request, "Bearer");
        // need to verify that this is an admin client.
        Identifier acID = BasicIdentifier.newID(credentials[HeaderUtils.ID_INDEX]);
        if (!getOA2SE().getAdminClientStore().containsKey(acID)) {
            throw new GeneralException("Error: the given id of \"" + acID + "\" is not recognized as an admin client.");
        }
        AdminClient adminClient = getOA2SE().getAdminClientStore().get(acID);
        String adminSecret = credentials[HeaderUtils.SECRET_INDEX];
        if (adminSecret == null || adminSecret.isEmpty()) {
            throw new GeneralException("Error: missing secret.");
        }

        String hashedSecret = DigestUtils.sha1Hex(adminSecret);
        if (!adminClient.getSecret().equals(hashedSecret)) {
            throw new IllegalAccessException("error: client and secret do not match");
        }
        return adminClient;
    }

    PermissionServer permissionServer = null;

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        AdminClient adminClient = getAndCheckAdminClient(httpServletRequest);
        // Now that we have the admin client (so we can do this request), we read the payload:
        JSON rawJSON = getPayload(httpServletRequest);

        DebugUtil.trace(this, rawJSON.toString());
        if (rawJSON.isArray()) {
            getMyLogger().info("Error: Got a JSON array rather than a request:" + rawJSON);
            throw new IllegalArgumentException("Error: incorrect argument. Not a valid JSON request");
        }
        OA2Client client = processRegistrationRequest((JSONObject) rawJSON, httpServletResponse);
        JSONObject resp = new JSONObject(); // The response object.
        resp.put(OIDCCMConstants.client_id, client.getIdentifierString());
        resp.put(OIDCCMConstants.CLIENT_SECRET, client.getSecret());
        // Now make a hash of the secret and store it.
        resp.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, client.getCreationTS().getTime() / 1000);
        String secret = DigestUtils.sha1Hex(client.getSecret());
        client.setSecret(secret);
        resp.put(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT, 0L);
        String registrationURI = getOA2SE().getCmConfigs().getRFC7591Config().uri.toString();
        // Next, we have to construct the registration URI by adding in the client ID.
        // Spec says we can add parameters here, but not elsewhere.
        resp.put(OIDCCMConstants.REGISTRATION_CLIENT_URI, registrationURI + "?" + OA2Constants.CLIENT_ID + "=" + client.getIdentifierString());
        ;

        getOA2SE().getClientStore().save(client);

        // this adds the client to the list of clients managed by the admin
        AddClientRequest addClientRequest = new AddClientRequest(adminClient, client);
        getPermissionServer().addClient(addClientRequest);

        // Finally, approve it since it was created with and admin client, which is assumed to be trusted
        ClientApproval approval = new ClientApproval(client.getIdentifier());
        approval.setApprovalTimestamp(new Date());
        approval.setApprover(adminClient.getIdentifierString());
        approval.setApproved(true);
        approval.setStatus(ClientApproval.Status.APPROVED);
        getOA2SE().getClientApprovalStore().save(approval);

        writeOK(httpServletResponse, resp);
    }

    private void writeOK(HttpServletResponse httpServletResponse, JSONObject resp) throws IOException {
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().println(resp.toString());
        httpServletResponse.getWriter().flush(); // commit it
        httpServletResponse.setStatus(HttpStatus.SC_OK);
    }

    protected JSON getPayload(HttpServletRequest httpServletRequest) throws IOException {
        BufferedReader br = httpServletRequest.getReader();
        DebugUtil.trace(this, "query=" + httpServletRequest.getQueryString());
        StringBuffer stringBuffer = new StringBuffer();
        String line = br.readLine();
        DebugUtil.trace(this, "line=" + line);
        while (line != null) {
            stringBuffer.append(line);
            line = br.readLine();
        }
        br.close();
        if (stringBuffer.length() == 0) {
            throw new IllegalArgumentException("Error: There is no content for this request");
        }
        return JSONSerializer.toJSON(stringBuffer.toString());
    }


    /**
     * Get the client from the request. Note that this may return  null if no such client exists and
     * it is up to the calling method to decide if this is ok.
     *
     * @param req
     * @return
     */
    protected OA2Client getClient(HttpServletRequest req) {
        String rawID = req.getParameter(OA2Constants.CLIENT_ID);
        if (rawID == null || rawID.isEmpty()) {
            return null;
        }
        return (OA2Client) getOA2SE().getClientStore().get(BasicIdentifier.newID(rawID));
    }

    protected OA2Client updateClient(OA2Client client, JSONObject jsonRequest, HttpServletResponse httpResponse) {
        OA2ClientKeys keys = new OA2ClientKeys();

        /*
        NOTE that this will check for required attributes, process them, then remove them from the JSON.
        This allows us to store the non-essential parameters in the request. At this point we keep
        them in case we need them, but we are not going to allocated actual storage for them, just folding them
        into the extra attributes of the client's configuration.
         */

        if (jsonRequest.containsKey(OIDCCMConstants.APPLICATION_TYPE)) {
            // optional but must be "web" if present
            if (!jsonRequest.getString(OIDCCMConstants.APPLICATION_TYPE).equals("web")) {
                throw new OA2GeneralError("Unsupported application type", OA2Errors.INVALID_REQUEST, "Unsupported application type",
                        HttpStatus.SC_BAD_REQUEST);
            }
        }

        jsonRequest.remove(OIDCCMConstants.APPLICATION_TYPE);
        if (jsonRequest.containsKey(OIDCCMConstants.GRANT_TYPES)) {
            // no grant type implies only authorization_code, not refresh_token. This is because the spec. allows for
            // implicit grants (which we do not) which forbid refresh_tokens.
            JSONArray grantTypes = jsonRequest.getJSONArray(OIDCCMConstants.GRANT_TYPES);
            // If the refresh token is requested, then the rtLifetime may be specified. if not, use server default.
            if (grantTypes.contains(OA2Constants.REFRESH_TOKEN)) {
                if (jsonRequest.containsKey(keys.rtLifetime())) {
                    client.setRtLifetime(jsonRequest.getLong(keys.rtLifetime()));
                } else {
                    // check if there is no RT lifetime specified, set it to the server max.
                    client.setRtLifetime(getOA2SE().getMaxClientRefreshTokenLifetime());
                }
            }
        } else {
            // disable refresh tokens.
            client.setRtLifetime(0L);
        }

        jsonRequest.remove(OIDCCMConstants.GRANT_TYPES);
        if (!jsonRequest.containsKey(OIDCCMConstants.REDIRECT_URIS)) {
            throw new OA2GeneralError("Error: Required parameter \"" + OIDCCMConstants.REDIRECT_URIS + "\" missing.",
                    OA2Errors.INVALID_REQUEST,
                    "Error: Required parameter \"" + OIDCCMConstants.REDIRECT_URIS + "\" missing.",
                    HttpStatus.SC_BAD_REQUEST);
        }
        JSONArray redirectURIs = jsonRequest.getJSONArray(OIDCCMConstants.REDIRECT_URIS);
        client.setCallbackURIs(redirectURIs);
        jsonRequest.remove(OIDCCMConstants.REDIRECT_URIS);
        // Now we do the stuff we think we need.
        if (!jsonRequest.containsKey(OIDCCMConstants.CLIENT_NAME)) {
            throw new OA2GeneralError("Error: no client name", OA2Errors.INVALID_REQUEST, HttpStatus.SC_BAD_REQUEST);
        }
        client.setName(jsonRequest.getString(OIDCCMConstants.CLIENT_NAME));
        jsonRequest.remove(OIDCCMConstants.CLIENT_NAME);
        client.setSignTokens(true); // always for us.
        if (!jsonRequest.containsKey(OA2Constants.SCOPE)) {
            // no scopes and this is an OIDC server implies just the openid scope and this is a public client
            if (getOA2SE().isOIDCEnabled()) {
                client.getScopes().add(OA2Scopes.SCOPE_OPENID);
                client.setPublicClient(true);
            }
            // alternately, no scopes are set/required.
        } else {
            client.setScopes(jsonRequest.getJSONArray(OA2Constants.SCOPE));
        }
        jsonRequest.remove(OA2Constants.SCOPE);
        byte[] bytes = new byte[getOA2SE().getClientSecretLength()];
        random.nextBytes(bytes);
        String secret64 = Base64.encodeBase64URLSafeString(bytes);
        // we have to return this to the client registration ok page and store a hash of it internally
        // so we don't have a copy of it any place but the client.
        // After this is displayed the secret is actually hashed and stored.
        client.setSecret(secret64);
        JSONObject config = client.getConfig();
        if (config == null) {
            // Just in case there is no config.
            config = new JSONObject();
        }
        OA2ClientConfigurationUtil.setExtraAttributes(config, jsonRequest);
        client.setConfig(config);
        return client;

    }

    protected OA2Client processRegistrationRequest(JSONObject jsonRequest, HttpServletResponse httpResponse) {
        OA2Client client = (OA2Client) getOA2SE().getClientStore().create();
        return updateClient(client, jsonRequest, httpResponse);
    }

    SecureRandom random = new SecureRandom();
}
