package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.HeaderUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.EnvServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
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

/**
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

    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        throw new NotImplementedException("Get is not supported by this service");
    }

    @Override
    public void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
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
            doIt(httpServletRequest, httpServletResponse);
        } catch (Throwable t) {
            handleException(t, httpServletRequest, httpServletResponse);
        }
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        String[] credentials = HeaderUtils.getCredentialsFromHeaders(httpServletRequest, "Bearer");
        // need to verify that this is an admin client.
        Identifier acID = BasicIdentifier.newID(credentials[HeaderUtils.ID_INDEX]);
        if (!getOA2SE().getAdminClientStore().containsKey(acID)) {
            throw new GeneralException("Error: the given id of \"" + acID + "\" is not recognized as an admin client.");
        }
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
        JSON rawJSON = JSONSerializer.toJSON(stringBuffer.toString());

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

        getOA2SE().getClientStore().save(client);

        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().println(resp.toString());
        httpServletResponse.getWriter().flush(); // commit it 
        httpServletResponse.setStatus(HttpStatus.SC_OK);
    }


    protected OA2Client processRegistrationRequest(JSONObject jsonRequest, HttpServletResponse httpResponse) {
        OA2Client client = (OA2Client) getOA2SE().getClientStore().create();
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

    SecureRandom random = new SecureRandom();
}
