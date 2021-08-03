package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.AddClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.RemoveClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.HeaderUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.EnvServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
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
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMConstants.CLIENT_ID;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMConstants.CLIENT_SECRET;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMConstants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.RFC8693Constants.GRANT_TYPE_TOKEN_EXCHANGE;

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
        //      printAllParameters(httpServletRequest);
        if (doPing(httpServletRequest, httpServletResponse)) return;
        if (!getOA2SE().getCmConfigs().hasRFC7591Config()) {
            throw new IllegalAccessError("Error: RFC 7591 not supported on this server. Request rejected.");
        }

        try {
            AdminClient adminClient = getAndCheckAdminClient(httpServletRequest); // Need this to verify admin client.
            MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(adminClient);
            debugger.trace(this, "Starting get");
            String rawID = getFirstParameterValue(httpServletRequest, OA2Constants.CLIENT_ID);
            if (rawID == null || rawID.isEmpty()) {
                throw new GeneralException("Missing client id. Cannot process request");
            }
            Identifier id = BasicIdentifier.newID(rawID);
            OA2Client client = (OA2Client) getOA2SE().getClientStore().get(id);
            if (client == null) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "no such client",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
            debugger.trace(this, "   requested client is " + client.getIdentifierString());

            // One major difference is that we have an email that we store and this has to be
            // converted to a contacts array or we run the risk of inadvertantly losing this.

            JSONObject json = toJSONObject(client);
            if (adminClient.isDebugOn()) {
                fireMessage(getOA2SE(), defaultReplacements(httpServletRequest, adminClient, client));
            }
            writeOK(httpServletResponse, json); //send it back with an ok.
        } catch (Throwable t) {
            handleException(t, httpServletRequest, httpServletResponse);
        }
    }

    protected HashMap<String, String> defaultReplacements(HttpServletRequest req, AdminClient adminClient, OA2Client client) {
        HashMap<String, String> replacements = new HashMap<>();
        replacements.put("admin_id", adminClient.getIdentifierString());
        replacements.put("client_id", client.getIdentifierString());
        replacements.put("action", req.getMethod());
        return replacements;
    }

    /**
     * Take a client and turn it in to a response object. This is used by both GET do PUT (which is supposed
     * to return the same output as GET when done with its updates)
     *
     * @param client
     * @return
     */
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

        if (client.getGrantTypes().isEmpty()) {
            /*JSONArray grants = new JSONArray();
            grants.add(OA2Constants.GRANT_TYPE_AUTHORIZATION_CODE);
            if (client.isRTLifetimeEnabled()) {
                grants.add(OA2Constants.REFRESH_TOKEN);
            }*/
        } else {
            json.put(OIDCCMConstants.GRANT_TYPES, client.getGrantTypes());
        }
        if (!client.getResponseTypes().isEmpty()) {

            json.put(RESPONSE_TYPES, client.getResponseTypes());
        }
        if (client.isPublicClient()) {
            json.put(TOKEN_ENDPOINT_AUTH_METHOD, TOKEN_ENDPOINT_AUTH_NONE);
        }
        if (client.getRtLifetime() != 0) {
            // Stored in ms., sent/received in sec. Convert to seconds.
            json.put(REFRESH_LIFETIME, client.getRtLifetime() / 1000);
        } else {
            json.put(REFRESH_LIFETIME, 0L);
        }
        if (0 != client.getAtLifetime()) {
            // Stored in ms., sent/received in sec. Convert to seconds.
            json.put(ACCESS_TOKEN_LIFETIME, client.getRtLifetime() / 1000);
        } else {
            json.put(ACCESS_TOKEN_LIFETIME, 0L);
        }

        JSONArray scopes = new JSONArray();
        scopes.addAll(client.getScopes());
        json.put(OA2Constants.SCOPE, scopes);
        json.put(OIDCCMConstants.CLIENT_URI, client.getHomeUri());
        json.put(OA2Constants.ERROR_URI, client.getErrorUri());
        // CIL-931 fix.
        json.put(STRICT_SCOPES, client.useStrictScopes());
        // Note that a contact email is something specific to OA4MP and does not occur in
        // either RFC 7591 or 7592.
        json.put("email", client.getEmail());
        // This is in seconds since the epoch
        json.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, client.getCreationTS().getTime() / 1000);
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {

            json.put("cfg", client.getConfig());
        }
        OA2ClientKeys clientKeys = (OA2ClientKeys) getOA2SE().getClientStore().getMapConverter().getKeys();
        if (json.containsKey(clientKeys.email())) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.add(json.get(clientKeys.email()));
            json.remove(clientKeys.email());
            json.put(OIDCCMConstants.CONTACTS, jsonArray);
        }
        if (client.hasOIDC_CM_Attributes()) {
            // add them back
            for (Object key : client.getOIDC_CM_Attributes().keySet()) {
                json.put(key, client.getOIDC_CM_Attributes().get(key));
            }
        }
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
        //     printAllParameters(req);
        if (!getOA2SE().getCmConfigs().hasRFC7592Config()) {
            throw new IllegalAccessError("Error: RFC 7592 not supported on this server. Request rejected.");
        }

        try {
            AdminClient adminClient = getAndCheckAdminClient(req);
            MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(adminClient);
            String rawID = req.getParameter(OA2Constants.CLIENT_ID);
            debugger.trace(this, "Starting delete request for admin client " + adminClient.getIdentifierString() + "\n" +
                    "for client id =\"" + rawID + "\"");
            if (rawID == null || rawID.isEmpty()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "Missing client id", HttpStatus.SC_BAD_REQUEST, null);
            }
            OA2Client client = (OA2Client) getOA2SE().getClientStore().get(BasicIdentifier.newID(rawID));
            if (client == null) {
                // Then this client does not exist on this server. Spec. says this is all fine and good
                resp.setStatus(HttpStatus.SC_NO_CONTENT);
                return;
            }
            debugger.trace(this, "checking permissions");
            checkAdminPermission(adminClient, client);

            // remove it from the store, then remove it from the approvals.
            // only admin clients can delete a client.
            debugger.trace(this, "removing approval");
            getOA2SE().getClientApprovalStore().remove(client.getIdentifier());
            debugger.trace(this, "removing client from store");
            getOA2SE().getClientStore().remove(client.getIdentifier());
            // That removes it from storage, now remove it from the permission list for this admin client.
            RemoveClientRequest removeClientRequest = new RemoveClientRequest(adminClient, client);
            debugger.trace(this, "removing all permissions.");
            getPermissionServer().removeClient(removeClientRequest);
            debugger.trace(this, "done with remove. Writing response.");
            resp.setStatus(HttpStatus.SC_NO_CONTENT); // no content is as per spec
            if (adminClient.isDebugOn()) {
                // CIL-607
                fireMessage(getOA2SE(), defaultReplacements(req, adminClient, client));
            }
            return;
        } catch (Throwable t) {
            handleException(t, req, resp);
        }
    }

    /**
     * Checks that this client exists on the system and that if it exists, the admin client actually
     * owns it.
     *
     * @param adminClient
     * @param client
     */
    protected void checkAdminPermission(AdminClient adminClient, OA2Client client) {
        if (client == null) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                    "unknown client",
                    HttpStatus.SC_UNAUTHORIZED, // as per spec
                    null
            );
        }
        // now we check that this admin owns this client
        List<Identifier> clientList = getOA2SE().getPermissionStore().getClients(adminClient.getIdentifier());
        if (!clientList.contains(client.getIdentifier())) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED,
                    "access denied",
                    HttpStatus.SC_FORBIDDEN, // as per spec.
                    null
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
        //   printAllParameters(req);

        if (!getOA2SE().getCmConfigs().hasRFC7592Config()) {
            throw new IllegalAccessError("Error: RFC 7592 not supported on this server. Request rejected.");
        }
        try {
            AdminClient adminClient = getAndCheckAdminClient(req);
            MetaDebugUtil adminDebugger = MyProxyDelegationServlet.createDebugger(adminClient);
            OA2Client client = getClient(req);
            checkAdminPermission(adminClient, client);

            JSON rawJSON = getPayload(req, adminDebugger);

            adminDebugger.trace(this, rawJSON.toString());
            if (rawJSON.isArray()) {
                adminDebugger.info(this, "Error: Got a JSON array rather than a request:" + rawJSON);
                throw new IllegalArgumentException("Error: incorrect argument. Not a valid JSON request");
            }
            JSONObject jsonRequest = (JSONObject) rawJSON;

            if (jsonRequest.size() == 0) {
                // Playing nice here. If they upload an empty object, the net effect is going to be to zero out
                // everything for this client except the id. The assumption is they don't want to do that.
                adminDebugger.info(this, "Error: Got an empty JSON object. Request rejected.");
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "invalid request",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            //have to check that certain key/values are excluded from the update.
            if (jsonRequest.containsKey(OIDCCMConstants.REGISTRATION_ACCESS_TOKEN) ||
                    jsonRequest.containsKey(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT) ||
                    jsonRequest.containsKey(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT) ||
                    jsonRequest.containsKey(OIDCCMConstants.CLIENT_ID_ISSUED_AT)) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "invalid parameter",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            if (jsonRequest.containsKey(OA2Constants.SCOPE)) {
                // the only thing that we are concerned with is is client is attempting to increase their
                // scopes. The are permitted to reduce them.
                boolean rejectRequest = false;
                JSONArray newScopes = toJA(jsonRequest, OA2Constants.SCOPE);
                Collection<String> oldScopes = client.getScopes();
                // Fix for CIL-775
                if (client.isPublicClient()) {
                    if (oldScopes.size() == 1 && oldScopes.contains(OA2Scopes.SCOPE_OPENID)) {
                        // This is a public client. they are allowed to re-assert it
                        if (!(newScopes.size() == 1 && newScopes.contains(OA2Scopes.SCOPE_OPENID))) {
                            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                                    "Cannot increase scope of public client.",
                                    HttpStatus.SC_BAD_REQUEST,
                                    null);
                        }
                    }

                }
                Collection<String> newScopeList = new HashSet<>();
                // Fix for CIL-725 Allow admin clients to alter scopes as desired.
                // NOTE as long as this admin-only access this is ok. Otherwise the
                // previous version the only permits a reduction in scopes is allowed.
                // We do reject a scope if it is not on the supported list for this server
                Collection<String> supportedScopes = getOA2SE().getScopes();

                for (Object x : newScopes) {
                    String scope = x.toString();
                    if (!supportedScopes.contains(scope)) {
                        // then this is not in the list, request is rejected
                        rejectRequest = true;
                        break;
                    }
                    newScopeList.add(scope);
                }
                if (rejectRequest) {
                    throw new OA2GeneralError(OA2Errors.INVALID_SCOPE,
                            "invalid scope",
                            HttpStatus.SC_FORBIDDEN, // as per spec, section RFC 7592 section 2.2
                            null
                    );
                }
                client.setScopes(newScopeList);
            }
            // so we create a new client, set the secret and id, then update that. This way if
            // this fails we can just back out.
            OA2Client newClient = (OA2Client) getOA2SE().getClientStore().create();
            boolean generateNewSecret = false;
            if (jsonRequest.containsKey(CLIENT_SECRET)) {
                // then we have to check this is a valid client. If this is missing, then
                // we are being requested to generate a new secret.
                String hashedSecret = DigestUtils.sha1Hex(jsonRequest.getString(CLIENT_SECRET));
                if (!hashedSecret.equals(client.getSecret())) {
                    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                            "client id does not match",
                            HttpStatus.SC_FORBIDDEN,
                            null);
                }
                newClient.setSecret(client.getSecret());  // it matches, send it along.
            }
            // Fix for CIL-778.
            // Make sure that the newClient (scratch copy in case we bail)  always has the secret
            // or this effectively resets it to null (!!) and disables any subsequent attempt to use it.
            newClient.setSecret(client.getSecret());
            // Being a public client is decided at registration based on scopes and auth type. We have
            // to faithfully transmit this in the newClient since it cannot be determined otherwise.
            newClient.setPublicClient(client.isPublicClient()); // or updates for public clients are impossible.
            // Make sure these are missing so we don't get them stashed someplace.
            jsonRequest.remove(CLIENT_SECRET);
            jsonRequest.remove(CLIENT_ID);

            newClient.setIdentifier(client.getIdentifier());
            newClient.setConfig(client.getConfig());
            try {
                newClient = updateClient(newClient, adminClient, jsonRequest, false, resp);

                getOA2SE().getClientStore().save(newClient);
                writeOK(resp, toJSONObject(newClient));
                //     writeOK(resp, resp);

            } catch (Throwable t) {
                // back out of it
                warn("Error attempting to update client \"" + client.getIdentifierString() + "\". " +
                        "Message = \"" + t.getMessage() + "\". Request is rejected");
                // resp.setStatus(HttpStatus.SC_BAD_REQUEST);
                handleException(t, req, resp);
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
            DebugUtil.trace(this, "ENCODING is of type " + httpServletRequest.getContentType());
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
     *
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
        MetaDebugUtil adminDebugger = MyProxyDelegationServlet.createDebugger(adminClient);
        String adminSecret = credentials[HeaderUtils.SECRET_INDEX];
        if (adminSecret == null || adminSecret.isEmpty()) {
            throw new GeneralException("Error: missing secret.");
        }
        if (!getOA2SE().getClientApprovalStore().isApproved(acID)) {
            adminDebugger.trace(this, "Admin client \"" + acID + "\" is not approved.");
            throw new GeneralException("error: This admin client has not been approved.");
        }
        String hashedSecret = DigestUtils.sha1Hex(adminSecret);
        if (!adminClient.getSecret().equals(hashedSecret)) {
            adminDebugger.trace(this, "Admin client \"" + acID + "\" and secret do not match.");
            throw new GeneralException("error: client and secret do not match");
        }
        return adminClient;
    }

    PermissionServer permissionServer = null;

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {

        AdminClient adminClient = getAndCheckAdminClient(httpServletRequest);
        MetaDebugUtil adminDebugger = MyProxyDelegationServlet.createDebugger(adminClient);
        adminDebugger.trace(this, "Starting to process " + httpServletRequest.getMethod());
        // Now that we have the admin client (so we can do this request), we read the payload:
        JSON rawJSON = getPayload(httpServletRequest, adminDebugger);
        if (adminClient.getMaxClients() < getOA2SE().getPermissionStore().getClientCount(adminClient.getIdentifier())) {
            adminDebugger.info(this, "Error: Max client count of " + adminClient.getMaxClients() + " exceeded.");
            throw new GeneralException("Error: Max client count of " + adminClient.getMaxClients() + " exceeded.");
        }
        adminDebugger.trace(this, rawJSON.toString());
        if (rawJSON.isArray()) {
            adminDebugger.info(this, "Error: Got a JSON array rather than a request:" + rawJSON);
            throw new IllegalArgumentException("Error: incorrect argument. Not a valid JSON request");
        }
        OA2Client client = processRegistrationRequest((JSONObject) rawJSON, adminClient, httpServletResponse);
        if (adminClient.isDebugOn()) {
            // CIL-607
            fireMessage(getOA2SE(), defaultReplacements(httpServletRequest, adminClient, client));
        }

        JSONObject jsonResp = new JSONObject(); // The response object.
        jsonResp.put(CLIENT_ID, client.getIdentifierString());
        if (!StringUtils.isTrivial(client.getSecret())) {

            jsonResp.put(CLIENT_SECRET, client.getSecret());
            String hashedSecret = DigestUtils.sha1Hex(client.getSecret());
            // Now make a hash of the secret and store it.
            jsonResp.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, client.getCreationTS().getTime() / 1000);
            String secret = DigestUtils.sha1Hex(client.getSecret());
            client.setSecret(secret);
            jsonResp.put(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT, 0L);

        }
        String registrationURI = getOA2SE().getCmConfigs().getRFC7591Config().uri.toString();
        // Next, we have to construct the registration URI by adding in the client ID.
        // Spec says we can add parameters here, but not elsewhere.
        jsonResp.put(OIDCCMConstants.REGISTRATION_CLIENT_URI, registrationURI + "?" + OA2Constants.CLIENT_ID + "=" + client.getIdentifierString());

        adminDebugger.trace(this, "saving this client");
        getOA2SE().getClientStore().save(client);

        // this adds the client to the list of clients managed by the admin
        adminDebugger.trace(this, "Adding permissions for this client");
        AddClientRequest addClientRequest = new AddClientRequest(adminClient, client);
        getPermissionServer().addClient(addClientRequest);

        // Finally, approve it since it was created with and admin client, which is assumed to be trusted
        adminDebugger.trace(this, "Setting approval record for this client");
        ClientApproval approval = new ClientApproval(client.getIdentifier());
        approval.setApprovalTimestamp(new Date());
        approval.setApprover(adminClient.getIdentifierString());
        approval.setApproved(true);
        approval.setStatus(ClientApproval.Status.APPROVED);
        getOA2SE().getClientApprovalStore().save(approval);

        writeOK(httpServletResponse, jsonResp);
    }

    private void writeOK(HttpServletResponse httpServletResponse, JSONObject resp) throws IOException {
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().println(resp.toString());
        httpServletResponse.getWriter().flush(); // commit it
        httpServletResponse.setStatus(HttpStatus.SC_OK);
    }

    protected JSON getPayload(HttpServletRequest httpServletRequest, MetaDebugUtil adminDebugger) throws IOException {
        BufferedReader br = httpServletRequest.getReader();
        adminDebugger.trace(this, "query=" + httpServletRequest.getQueryString());
        StringBuffer stringBuffer = new StringBuffer();
        String line = br.readLine();
        adminDebugger.trace(this, "line=" + line);
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

    protected OA2Client updateClient(OA2Client client,
                                     AdminClient adminClient,
                                     JSONObject jsonRequest,
                                     boolean newClient,
                                     HttpServletResponse httpResponse) {
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
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "Unsupported application type",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
        }

        jsonRequest.remove(OIDCCMConstants.APPLICATION_TYPE);
        handleGrants(client, jsonRequest, keys);
        handleResponseTypes(client, jsonRequest, keys);
        JSONArray redirectURIs;
        if (jsonRequest.containsKey(OIDCCMConstants.REDIRECT_URIS)) {
            redirectURIs = jsonRequest.getJSONArray(OIDCCMConstants.REDIRECT_URIS);
        } else {
            redirectURIs = new JSONArray(); // just take it as an empty list
        }
        // URI sanity check. Since it's JSON they could send garbage.
        // Wildcard check for CIL-871
        for (Object z : redirectURIs) {
            if (!(z instanceof String)) {
                throw new OA2GeneralError(
                        OA2Errors.INVALID_REQUEST,
                        "Error: illegal redirect uri \"" + z + "\" ",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            if (z.toString().contains("*")) {
                throw new OA2GeneralError(
                        OA2Errors.INVALID_REQUEST,
                        "Error: wildcards not allows in redirect uri \"" + z + "\" ",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
        }
        client.setCallbackURIs(redirectURIs);
        jsonRequest.remove(OIDCCMConstants.REDIRECT_URIS);
        // Now we do the stuff we think we need.
        if (!jsonRequest.containsKey(OIDCCMConstants.CLIENT_NAME)) {
            throw new OA2GeneralError(
                    OA2Errors.INVALID_REQUEST,
                    "Error: no client name",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }
        client.setName(jsonRequest.getString(OIDCCMConstants.CLIENT_NAME));
        jsonRequest.remove(OIDCCMConstants.CLIENT_NAME);
        if (jsonRequest.containsKey(OIDCCMConstants.CLIENT_URI)) {
            // The client **should** have this but it not requred,
            client.setHomeUri(jsonRequest.getString(OIDCCMConstants.CLIENT_URI));
            jsonRequest.remove(OIDCCMConstants.CLIENT_URI);
        } else {
            client.setHomeUri(""); // not great, but...
        }
        if (jsonRequest.containsKey(TOKEN_ENDPOINT_AUTH_METHOD)) {
            // not required, but if present, we support exactly two nontrivial options.
            JSONArray jsonArray = toJA(jsonRequest, TOKEN_ENDPOINT_AUTH_METHOD);
            boolean gotSupportedAuthMethod = false;
            if (jsonArray.contains(OA2Constants.TOKEN_ENDPOINT_AUTH_NONE)) {
                if (newClient) {
                    gotSupportedAuthMethod = true;
                    client.setPublicClient(true);

                } else {
                    if (client.isPublicClient()) {
                        // CIL-884.
                        // do nothing -- let them udpdate everything else but the
                        // their confidentiality status.
                        gotSupportedAuthMethod = true;

                    } else {
                        // Don't let admins change client confidential --> public
                        throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                                "cannot change from a confidential to a public client",
                                HttpStatus.SC_BAD_REQUEST, null);

                    }
                }
            } else {

                if (jsonArray.contains(OA2Constants.TOKEN_ENDPOINT_AUTH_POST) ||
                        jsonArray.contains(OA2Constants.TOKEN_ENDPOINT_AUTH_BASIC)) {
                    if (!newClient && client.isPublicClient()) {
                        // Only if this is already true do we throw an exception.
                        // This means it was public (=no secret) and now they want
                        // a secret.  We don't re-issue secrets. They have to register a new client
                        // to get a secret.
                        throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                                "cannot change from a public to a confidential client",
                                HttpStatus.SC_BAD_REQUEST, null);

                    }
                    gotSupportedAuthMethod = true;
                    client.setPublicClient(false);
                    client.setSignTokens(true); // always for us.
                }

            }
            if (!gotSupportedAuthMethod) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                        "unsupported token endpoint authorization method",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
            jsonRequest.remove(TOKEN_ENDPOINT_AUTH_METHOD);
        }
        if (!jsonRequest.containsKey(OA2Constants.SCOPE)) {
            client.setScopes(new ArrayList<>()); // zeros it out
            // NOTE We no longer require that a client set scopes. If the server is OIDC aware
            // then that should just mean it accepts the openid scope and if missing
            // does not return much (like no subject or id token), For some clients
            // that just want an access token, that is fine.

            // ---------- old stuff. Keep for a bit.
            // no scopes and this is an OIDC server implies just the openid scope and this is a public client
           /*
            if (getOA2SE().isOIDCEnabled()) {
                client.getScopes().add(OA2Scopes.SCOPE_OPENID);
                client.setPublicClient(true);
            }
            */
        } else {
            JSONArray newScopes = toJA(jsonRequest, OA2Constants.SCOPE);
            if (client.isPublicClient()) {
                // public clients cannot reset their scopes ever.
                // They must, however, send along a single openid scope or this gets flagged as an error
                if (!newScopes.contains(OA2Scopes.SCOPE_OPENID)) {
                    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                            "cannot decrease scope on a public client.",
                            HttpStatus.SC_BAD_REQUEST, null);
                }
                if (1 < newScopes.size()) {
                    throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                            "cannot increase scopes on a public client.",
                            HttpStatus.SC_BAD_REQUEST, null);
                }
            }
            client.setScopes(newScopes);
        }
        jsonRequest.remove(OA2Constants.SCOPE);
        // Only generate a secret if allowed (the flag denotes that it is ok to generate one here)
        // and if the client is not public <==> the auth method is "none"
        if (newClient) {
            if (client.isPublicClient()) {
                client.setSecret("");
            } else {
                byte[] bytes = new byte[getOA2SE().getClientSecretLength()];
                random.nextBytes(bytes);
                String secret64 = Base64.encodeBase64URLSafeString(bytes);
                client.setSecret(secret64);
            }
        }
        if (jsonRequest.containsKey(OIDCCMConstants.CONTACTS)) {
            // This is a set of strings thjat are typically email addresses.
            // Todo: Really check these and allow for multiple values
            // Todo: This takes only the very first.
            JSONArray emails = toJA(jsonRequest, OIDCCMConstants.CONTACTS);
            //= jsonRequest.getJSONArray(OIDCCMConstants.CONTACTS);
            ServletDebugUtil.info(this, "Multiple contacts addresses found " + emails + "\n Only the first is used currently.");
            if (!emails.isEmpty()) {
                client.setEmail(emails.getString(0));
            }
            jsonRequest.remove(OIDCCMConstants.CONTACTS);
        }
        //CIL-703

        if (jsonRequest.containsKey("cfg")) {
            if (client.isPublicClient()) {
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                        "custom configurations not permitted in public clients.",
                        HttpStatus.SC_BAD_REQUEST, null);

            }
            JSONObject jsonObject = jsonRequest.getJSONObject("cfg");
            // CIL-889 fix
            if (!adminClient.isAllowQDL() && jsonRequest.getString("cfg").contains("qdl")) {
                // Pretty draconian test -- any tag for QDL gets booted.
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST_OBJECT,
                        "QDL scripting is not allowed for this client.",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
            jsonRequest.remove("cfg");
            client.setConfig(jsonObject);
        } else {
            // CIL-735 if not config object, remove it. 
            client.setConfig(null);
        }

        if (jsonRequest.containsKey(REFRESH_LIFETIME)) {
            // NOTE this is sent in seconds but is recorded as ms., so convert to milliseconds here.
            client.setRtLifetime(jsonRequest.getLong(REFRESH_LIFETIME) * 1000);
            jsonRequest.remove(REFRESH_LIFETIME);
        }
        if (jsonRequest.containsKey(ACCESS_TOKEN_LIFETIME)) {
            // NOTE this is sent in seconds but is recorded as ms., so convert to milliseconds here.
            client.setAtLifetime(jsonRequest.getLong(ACCESS_TOKEN_LIFETIME) * 1000);
            jsonRequest.remove(ACCESS_TOKEN_LIFETIME);
        }
        if (jsonRequest.containsKey(STRICT_SCOPES)) {
            client.setStrictscopes(jsonRequest.getBoolean(STRICT_SCOPES));
            jsonRequest.remove(STRICT_SCOPES);
        }
        // Fix for CIL-734: now handle everything else left over
        client.removeOIDC_CM_Attributes();
        if (!jsonRequest.isEmpty()) {
            client.setOIDC_CM_attributes(jsonRequest);
        }
        return client;

    }

    /**
     * TL;DR: we support the grant types for the authorization_code flow so only code and id_token.
     * We explicitly reject every other response_type at this point, in particular, we reject
     * the value of "token" which is only for the implicit flow.
     *
     * @param client
     * @param jsonRequest
     * @param keys
     */
    protected void handleResponseTypes(OA2Client client, JSONObject jsonRequest, OA2ClientKeys keys) {
        if (jsonRequest.containsKey(RESPONSE_TYPES)) {
            JSONArray responseTypes = toJA(jsonRequest, RESPONSE_TYPES);
            if (!responseTypes.contains(OA2Constants.RESPONSE_TYPE_CODE)) {
                throw new OA2GeneralError(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                        "unsupported response type",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
            if (responseTypes.contains(OA2Constants.RESPONSE_TYPE_TOKEN)) {
                // This is required for implicit flow, which we do not support.
                throw new OA2GeneralError(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                        "unsupported response type",
                        HttpStatus.SC_BAD_REQUEST, null);

            }
            if (1 < responseTypes.size() && !checkJAEntry(responseTypes, OA2Constants.RESPONSE_TYPE_ID_TOKEN)) {
                throw new OA2GeneralError(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                        "unsupported response type",
                        HttpStatus.SC_BAD_REQUEST, null);

            }
            client.setResponseTypes(responseTypes);
        } else {
            // Maybe add in defaults at some point if omitted? Now this works since we only have a single flow.
        }
        jsonRequest.remove(RESPONSE_TYPES);
    }

    /**
     * JSONArray does not check its contains sanely against strings at times.
     *
     * @param jsonArray
     * @param entry
     * @return
     */
    protected boolean checkJAEntry(JSONArray jsonArray, String entry) {
        for (int i = 0; i < jsonArray.size(); i++) {
            if (jsonArray.getString(i).equals(entry)) return true;
        }
        return false;
    }

    protected boolean areAllGrantsSupported(JSONArray proposedGrants, String[] supportedGrants) {
        for (int i = 0; i < proposedGrants.size(); i++) {
            boolean oneOK = false;
            for (int j = 0; j < supportedGrants.length; j++) {
                oneOK = oneOK || StringUtils.equals(proposedGrants.getString(i), supportedGrants[j]);
            }
            if (!oneOK) return false;
        }
        return true;
    }

    protected void handleGrants(OA2Client client, JSONObject jsonRequest, OA2ClientKeys keys) {
        if (jsonRequest.containsKey(OIDCCMConstants.GRANT_TYPES)) {
            // no grant type implies only authorization_code (as per RFC 7591, section2),
            // not refresh_token. This is because the spec. allows for
            // implicit grants (which we do not) which forbid refresh_tokens.
            // Fixes CIL-701
            JSONArray grantTypes = toJA(jsonRequest, OIDCCMConstants.GRANT_TYPES);
            String[] supportedGrants = new String[]{OA2Constants.GRANT_TYPE_AUTHORIZATION_CODE,
                    OA2Constants.GRANT_TYPE_REFRESH_TOKEN, GRANT_TYPE_TOKEN_EXCHANGE};
            if (!areAllGrantsSupported(grantTypes, supportedGrants)) {
                throw new OA2GeneralError(OA2Errors.REGISTRATION_NOT_SUPPORTED,
                        "unsupported grant type ",
                        HttpStatus.SC_BAD_REQUEST,
                        null);
            }
            boolean requestedRT = false;

            client.setGrantTypes(grantTypes);
            for (int i = 0; i < grantTypes.size(); i++) {
                if (grantTypes.getString(i).equals(OA2Constants.GRANT_TYPE_REFRESH_TOKEN)) {
                    requestedRT = true;
                    break;
                }
            }
            // If the refresh token is requested, then the rtLifetime may be specified. if not, use server default.
            if (requestedRT) {
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
        jsonRequest.remove(GRANT_TYPES);

    }

    /**
     * Some attribute scan come over the wire as either arrays of string or as blank delimited strings,
     * e.g. scopes and grant types. Just figure it out and hand back the array.
     * Note this will remove duplicates.
     *
     * @param obj
     * @param key
     * @return
     */
    protected JSONArray toJA(JSONObject obj, String key) {
        try {
            return obj.getJSONArray(key);
        } catch (Throwable t) {
            // so they did not send along a JSON array. Other option is a string
            String rawScopes = obj.getString(key);
            StringTokenizer st = new StringTokenizer(rawScopes, " ");
            JSONArray jsonArray = new JSONArray();
            while (st.hasMoreTokens()) {
                String nextScope = st.nextToken();
                if (!jsonArray.contains(nextScope)) {
                    jsonArray.add(nextScope);
                }
            }
            return jsonArray;
        }
    }

    protected OA2Client processRegistrationRequest(JSONObject jsonRequest, AdminClient adminClient, HttpServletResponse httpResponse) {

        OA2Client client = (OA2Client) getOA2SE().getClientStore().create();
        return updateClient(client, adminClient, jsonRequest, true, httpResponse);
    }

    SecureRandom random = new SecureRandom();
    String subjectTemplate = "Client Management servlet ${action} notification";
    String messageTemplate = "The admin client with id ${admin_id} has performed a ${action}\n" +
            "for client with id ${client_id}";

    //CIL-607
    protected void fireMessage(OA2SE oa2SE, HashMap<String, String> replacements) {
        oa2SE.getMailUtil().sendMessage(subjectTemplate, messageTemplate, replacements, oa2SE.getNotifyACEventEmailAddresses());
    }
}
