package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CM7591Config;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.CMConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.AddClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.RemoveClientRequest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandlerThingie;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2HeaderUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.EnvServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2JSONException;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Scopes;
import edu.uiuc.ncsa.oa4mp.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.oa4mp.delegation.server.WrongPasswordException;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ExceptionHandlerThingie;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMConstants.CLIENT_ID;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMConstants.CLIENT_SECRET;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.oidc_cm.OIDCCMConstants.*;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.*;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants.GRANT_TYPE_TOKEN_EXCHANGE;
import static edu.uiuc.ncsa.security.servlet.HeaderUtils.getFirstParameterValue;

/**
 * Note that in all of these calls, the assumption is that an admin client has been requested and
 * approved out of band. The identifier and secret of that are used to make the bearer token that
 * allows access to the calls in this API. This implements both RFC 7591 and part of RFC 7592.
 * Mostly we do not allow the setting of client secrets via tha API and since we do not store them
 * (only a hash of them) we cannot return them. If a secret is lost, the only option is to register a new
 * client. <br/><br/>
 * Nota Bene: RFC 7592 is not intended to become a specification since there is too much variance in how
 * this can operate.
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/18 at  10:04 AM
 */
public class OIDCCMServlet extends EnvServlet {

    public static final String PROXY_CLAIMS_LIST = "proxy_claims_list";
    public static final String FORWARD_REQUEST_SCOPES_TO_PROXY = "forward_scopes_to_proxy";
    public static final String PROXY_REQUEST_SCOPES = "proxy_request_scopes";
    public static final String IS_SERVICE_CLIENT = "is_service_client";
    public static final String SERVICE_CLIENT_USERS = "service_client_users";
    public static final String ERSATZ_CLIENT_PROVISIONERS = "org.oa4mp:/ersatz/provisioners";
   // Version
    public static final String API_VERSION_LATEST = "latest";
    /**
     * They sent nothing explicit.
     */
    public static final String API_VERSION_NONE = "none";
    public static final String API_VERSION_5_4 = "v5.4";
    public static final String API_VERSION_5_5 = "v5.5";
    public static final String API_VERSION_KEY = "api_version";


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

    public static final String QUERY_PARAMETER = "query";


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
        String version = getVersion(getOA2SE().getCmConfigs().getRFC7592Config(), httpServletRequest);

          //ServletDebugUtil.printAllParameters(getClass(), httpServletRequest, true); // ∈
          // E.g. IF anonymous access is allowed on the server:
        // curl -k -X GET  https://localhost:9443/oauth2/oidc-cm?query=org.oa4mp%3A%2Fserver%23defaults
        try {
            if (!(getOA2SE().getCmConfigs().hasRFC7592Config() && getOA2SE().getCmConfigs().getRFC7592Config().enabled) && getOA2SE().getCmConfigs().isEnabled()) {
                throw new IllegalAccessError("RFC 7592 not supported on this server. Request rejected.");
            }
            if (doPing(httpServletRequest, httpServletResponse)) return;
            if (!getOA2SE().getCmConfigs().hasRFC7592Config()) {
                throw new IllegalAccessError("RFC 7592 not supported on this server. Request rejected.");
            }

            boolean isAnonymous = false;  // Meaning that a client is trying to get information
            AdminClient adminClient = null;
            try {
                adminClient = getAndCheckAdminClient(httpServletRequest); // Need this to verify admin client.
            } catch(IllegalArgumentException iax){
                if (!getOA2SE().getCmConfigs().getRFC7591Config().anonymousOK) {
                    IllegalAccessException illegalAccessException =
                            new IllegalAccessException(iax.getMessage() + ", anonymous access denied",iax.getCause());
                    throw illegalAccessException;
                }
                isAnonymous = true;

            } catch (Throwable ge) {
                DebugUtil.trace(ge.getMessage(), ge);
            }
            String[] query = httpServletRequest.getParameterValues(QUERY_PARAMETER);
          //  System.err.println(getClass().getSimpleName() + "query =" + Arrays.toString(query)); // ∈
            if (query != null && query.length != 0) {
         //       System.err.println(getClass().getSimpleName() + "checking server query"); // ∈
                handleServerQuery(adminClient, Arrays.asList(query), httpServletRequest, httpServletResponse);
                return;
            }
            OA2Client oa2Client = null;
            MetaDebugUtil debugger;
            if (isAnonymous) {
                // Here's the logic: If we allow anonymous access, then a client can get itself.
                // If the client is administered, then the request must come with an admin client
                // Do not allow an un-administered client to query anything.
                try {
                    oa2Client = getAndCheckOA2Client(httpServletRequest);
                }catch(IllegalArgumentException iax){
                    throw new IllegalArgumentException("Anonymous queries are not supported");
                }
                if (!getOA2SE().getPermissionStore().getAdmins(oa2Client.getIdentifier()).isEmpty()) {
                    throw new IllegalArgumentException("administered clients cannot query their properties, only their administrator can.");
                }
                debugger = MyProxyDelegationServlet.createDebugger(oa2Client);
            } else {
                debugger = MyProxyDelegationServlet.createDebugger(adminClient);
            }
            debugger.trace(this, "Starting get");
            if (debugger.getDebugLevel() == MetaDebugUtil.DEBUG_LEVEL_TRACE) {
                printAllParameters(httpServletRequest);
            }
            String rawID = getFirstParameterValue(httpServletRequest, OA2Constants.CLIENT_ID);
            if (rawID == null || rawID.isEmpty()) {
                // CIL-1092 : An unqualified GET from an admin returns a list of administered clients and names
                debugger.trace(this, "id = \"" + rawID + "\" for client listing");
                List<Identifier> clients = getOA2SE().getPermissionStore().getClients(adminClient.getIdentifier());
                JSONObject jsonObject = new JSONObject();
                JSONArray array = new JSONArray();
                for (Identifier id : clients) {
                    Client client = (Client) getOA2SE().getClientStore().get(id);
                    if (client == null) {
                        continue; // this means that the permission table has an orphan.
                    }
                    JSONObject j2 = new JSONObject();
                    // adding in Identifiers turns them into fugly beans. Return strings.
                    j2.put(OA2Constants.CLIENT_ID, id.toString());
                    String name = client.getName();
                    if (!StringUtils.isTrivial(name)) {
                        j2.put("name", name);
                    }
                    array.add(j2);
                }
                jsonObject.put("clients", array);
                writeOK(httpServletResponse, jsonObject); //send it back with an ok.
                return;
            }
            Identifier id = BasicIdentifier.newID(rawID);
            if (isAnonymous) {
                if (!oa2Client.getIdentifierString().equals(rawID)) {
                    throw new IllegalAccessException("clients cannot access information about any other client");
                }
            } else {
                // so it's adminstered and is legit
                oa2Client = (OA2Client) getOA2SE().getClientStore().get(id);
            }
            if (oa2Client == null) {
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST,
                        "no such client",
                        HttpStatus.SC_BAD_REQUEST, null);
            }
            debugger.trace(this, "   requested client is " + oa2Client.getIdentifierString());

            // One major difference is that we have an email that we store and this has to be
            // converted to a contacts array or we run the risk of inadvertantly losing this.
            JSONObject json = toJSONObject(oa2Client, version, true);
            // This next block would turn on messages every time a get is issued. Since
            // COManage has a groovy GUI that lets people surf clients, the output
            // was getting intolerable. Maybe someday re-enable this? Maybe.
  /*          if ((!isAnonymous) && adminClient.isDebugOn()) {
                fireMessage(getOA2SE(), defaultReplacements(httpServletRequest, adminClient, oa2Client));
            }*/
            debugger.trace(this, "GET returns payload\n" + json.toString(2));
            writeOK(httpServletResponse, json); //send it back with an ok.
        } catch (Throwable t) {
          //  t.printStackTrace(); // ∈
            handleException(new ExceptionHandlerThingie(t, httpServletRequest, httpServletResponse));
        }
    }

    /**
     * We do support queries against the server. These are sent as queries in a get and are of the form
     * <pre>
     *     query=org.oa4mp:/server/...
     * </pre>
     * At least initially the only one we do allow for is querying server defaults, so
     * <pre>
     *     query=org.oa4mp:/server/defaults
     * </pre>
     * which returns a JSON object of various server defaults like default lifetimes and maximums.
     *
     * @param queries
     * @param request
     * @param response
     */
    private void handleServerQuery(AdminClient adminClient, List<String> queries, HttpServletRequest request, HttpServletResponse response) throws IOException {
        JSONObject jsonObject = new JSONObject();
        // improvement for https://github.com/ncsa/oa4mp/issues/154
        if (queries.contains("org.oa4mp:/server#defaults")) {
            // most of the other server configuration information (such as scopes supported)
            // are in the well-known page, but there is no place for these.
            jsonObject.put(REFRESH_LIFETIME, getOA2SE().getRefreshTokenLifetime() / 1000);
            jsonObject.put(ACCESS_TOKEN_LIFETIME, getOA2SE().getAccessTokenLifetime() / 1000);
            jsonObject.put(ID_TOKEN_LIFETIME, getOA2SE().getIdTokenLifetime() / 1000);
            jsonObject.put(MAX_REFRESH_LIFETIME, getOA2SE().getMaxRTLifetime() / 1000);
            jsonObject.put(MAX_ACCESS_TOKEN_LIFETIME, getOA2SE().getMaxATLifetime() / 1000);
            jsonObject.put(MAX_ID_TOKEN_LIFETIME, getOA2SE().getMaxIdTokenLifetime() / 1000);
            jsonObject.put("idt_max_lifetime", getOA2SE().getMaxIdTokenLifetime() / 1000); // same tag as in client cfg
            jsonObject.put(AUTH_GRANT_TOKEN_LIFETIME, getOA2SE().getAuthorizationGrantLifetime() / 1000);
            jsonObject.put("use_server_default", OA2Client.USE_SERVER_DEFAULT);
            jsonObject.put("rt_lifetime_create_default", getOA2SE().getCmConfigs().getRFC7591Config().getDefaultRefreshTokenLifetime());
            jsonObject.put("rt_lifetime_update_default", getOA2SE().getCmConfigs().getRFC7592Config().getDefaultRefreshTokenLifetime());
            jsonObject.put("api_version_default", getDefaultAPIVersion()); // default version.
            JSONArray versions = new JSONArray();
            versions.add(API_VERSION_LATEST);
            versions.add(API_VERSION_5_5);
            versions.add(API_VERSION_5_4);
            jsonObject.put("api_versions", versions);  // version list supported on this server
            jsonObject.put(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_TAG, getOA2SE().getRtGracePeriod() / 1000);
            jsonObject.put(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_TAG, getOA2SE().getRtGracePeriod() / 1000);
            if (adminClient == null || !adminClient.hasVirtualOrganization()) {
                // Fix https://github.com/ncsa/oa4mp/issues/177
                jsonObject.put("issuer", getOA2SE().getIssuer());
                jsonObject.put("at_issuer", getOA2SE().getIssuer());
            } else {
                VirtualOrganization vo = (VirtualOrganization) getOA2SE().getVOStore().get(adminClient.getVirtualOrganization());
                jsonObject.put("issuer", vo.getIssuer());
                jsonObject.put("at_issuer", vo.getAtIssuer());
            }
        }
        writeOK(response, jsonObject);
    }

    protected String formatIdentifiable(Store store, Identifiable identifiable) {
        XMLMap map = new XMLMap();
        store.getXMLConverter().toMap(identifiable, map);
        if (identifiable instanceof OA2Client) {
            OA2ClientConverter cc = (OA2ClientConverter) store.getXMLConverter();
            map.remove(cc.getCK2().secret()); // Remove the secret from the email!
        }
        List<String> outputList = StringUtils.formatMap(map,
                null,
                true,
                false,
                2,
                120);
        StringBuffer stringBuffer = new StringBuffer();
        for (String x : outputList) {
            stringBuffer.append(x + "\n");
        }
        return stringBuffer.toString();
    }

    protected HashMap<String, String> defaultReplacements(HttpServletRequest req, AdminClient adminClient, OA2Client client) {
        HashMap<String, String> replacements = new HashMap<>();
        if (adminClient != null) {
            replacements.put("admin_id", adminClient.getIdentifierString());
            replacements.put("admin_name", adminClient.getName());
        }
        replacements.put("client_id", client.getIdentifierString());
        replacements.put("client", formatIdentifiable(getOA2SE().getClientStore(), client));
        String actionString;
        switch (req.getMethod()) {
            case "PUT":
                actionString = "updated";
                break;
            case "POST":
                actionString = "registered";
                break;
            case "DELETE":
                actionString = "deleted";
                break;
            case "GET":
                actionString = "got";
                break;
            default:
                actionString = "did a " + req.getMethod();
        }
        replacements.put("action", actionString);
        return replacements;
    }

    /**
     * Take a client and turn it in to a response object. This is used by both GET do PUT (which is supposed
     * to return the same output as GET when done with its updates)
     *
     * @param client
     * @return
     */
    protected JSONObject toJSONObject(OA2Client client, String version, boolean isGet) {
           switch (version){
               case API_VERSION_5_4:
                   return toJSONObject5_4(client,  isGet);
               case API_VERSION_5_5:
               case API_VERSION_LATEST:
               default:
                   return toJSONObject5_5(client, getDefaultAPIVersion(),  isGet);
           }

    }
    protected JSONObject toJSONObject5_5(OA2Client client, String version, boolean isGet) {
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
        boolean gotJWKSURI = false;
        if (client.hasJWKSURI()) {
            gotJWKSURI = true;
            json.put(JWKS_URI, client.getJwksURI().toString());
        }
        if (client.hasJWKS()) {
            if (gotJWKSURI) {
                throw new IllegalStateException("The specification explicitly forbids having both keys and a jwks uri. Request rejected");
            }
            JSONObject jwks = JSONWebKeyUtil.toJSON(client.getJWKS());
            json.put(JWKS, jwks);
        }
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
        json.put(ID_TOKEN_LIFETIME, lifetimeToSec(client.getIdTokenLifetime()));
        json.put(MAX_ID_TOKEN_LIFETIME, lifetimeToSec(client.getMaxIDTLifetime()));
        json.put(ACCESS_TOKEN_LIFETIME, lifetimeToSec(client.getAtLifetime()));
        json.put(MAX_ACCESS_TOKEN_LIFETIME, lifetimeToSec(client.getMaxATLifetime()));
        switch (version){
            case API_VERSION_NONE:
            case API_VERSION_LATEST:
            case API_VERSION_5_5:
                json.put(REFRESH_LIFETIME, lifetimeToSec(client.getRtLifetime()));
                json.put(MAX_REFRESH_LIFETIME, lifetimeToSec(client.getMaxRTLifetime()));
                break;

            case API_VERSION_5_4:
            if(isGet){
                if(0<client.getRtLifetime()){
                    json.put(REFRESH_LIFETIME, lifetimeToSec(client.getRtLifetime()));
                    json.put(MAX_REFRESH_LIFETIME, lifetimeToSec(client.getMaxRTLifetime()));
                }
            }else{
                json.put(REFRESH_LIFETIME, lifetimeToSec(client.getRtLifetime()));
                json.put(MAX_REFRESH_LIFETIME, lifetimeToSec(client.getMaxRTLifetime()));
            }
        }
        // Always assert these.
        json.put(REFRESH_LIFETIME, lifetimeToSec(client.getRtLifetime()));
        json.put(MAX_REFRESH_LIFETIME, lifetimeToSec(client.getMaxRTLifetime()));
        json.put(EA_SUPPORT, client.hasExtendedAttributeSupport());
        if (client.hasJWKS()) {
            json.put(JWKS, JSONWebKeyUtil.toJSON(client.getJWKS()));
        }
        if (client.hasJWKSURI()) {
            json.put(JWKS_URI, client.getJwksURI().toString());
        }
        JSONArray scopes = new JSONArray();
        scopes.addAll(client.getScopes());
        if(!scopes.isEmpty()) {
            json.put(OA2Constants.SCOPE, scopes);
        }
        json.put(OIDCCMConstants.CLIENT_URI, client.getHomeUri());
        json.put(OA2Constants.ERROR_URI, client.getErrorUri());
        // CIL-931 fix.
        json.put(STRICT_SCOPES, client.useStrictScopes());
        json.put(SKIP_SERVER_SCRIPTS, client.isSkipServerScripts());
        // Note that a contact email is something specific to OA4MP and does not occur in
        // either RFC 7591 or 7592.
        json.put("email", client.getEmail());
        // CIL-1221
        if(!client.getProxyClaimsList().isEmpty()) {
            json.put(PROXY_CLAIMS_LIST, client.getProxyClaimsList());
        }
        json.put(FORWARD_REQUEST_SCOPES_TO_PROXY, client.isForwardScopesToProxy());
        if(!client.getProxyRequestScopes().isEmpty()) {
            json.put(PROXY_REQUEST_SCOPES, client.getProxyRequestScopes());
        }
        json.put(IS_SERVICE_CLIENT, client.isServiceClient());
        JSONArray array = new JSONArray();
        array.addAll(client.getServiceClientUsers());
        json.put(SERVICE_CLIENT_USERS, array);
        OA2ClientKeys clientKeys = (OA2ClientKeys) getOA2SE().getClientStore().getMapConverter().getKeys();
        // Fix https://github.com/ncsa/oa4mp/issues/159
        json.put(clientKeys.rtGracePeriod(), client.getRtGracePeriod());
        json.put(clientKeys.extendsProvisioners(), client.isExtendsProvisioners());
        json.put(clientKeys.ersatzClient(), client.isErsatzClient());
        json.put(clientKeys.ersatzInheritIDToken(), client.isErsatzInheritIDToken());
        //CIL-1321 inheritance
        if (client.hasPrototypes()) {
            JSONArray jsonArray = new JSONArray();
            for (Identifier id : client.getPrototypes()) {
                jsonArray.add(id.toString());
            }
            json.put(clientKeys.prototypes(), jsonArray);
        }
        // This is in seconds since the epoch
        json.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, client.getCreationTS().getTime() / 1000);
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {

            json.put("cfg", client.getConfig());
        }
        if (json.containsKey(clientKeys.email())) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.add(json.get(clientKeys.email()));
            json.remove(clientKeys.email());
            json.put(OIDCCMConstants.CONTACTS, jsonArray);
        }
        if (client.hasOIDC_CM_Attributes()) {
            // add them back
            for (Object key : client.getOIDC_CM_Attributes().keySet()) {
                if (!key.equals(OA2Constants.CLIENT_ID)) {
                    // had a case where a client uploaded client_id as an extra attribute
                    // Don't allow the user to hot-rod the client id even by accident.
                    json.put(key, client.getOIDC_CM_Attributes().get(key));
                }
            }
        }
        return json;
    }

    protected JSONObject toJSONObject5_4(OA2Client client, boolean isGet) {
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
          if (client.hasJWKSURI()) {
              json.put(JWKS_URI, client.getJwksURI().toString());
          }
          if (client.hasJWKS()) {
              JSONObject jwks = JSONWebKeyUtil.toJSON(client.getJWKS());
              json.put(JWKS, jwks);
          }
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
          if (0 < client.getRtLifetime()) {
              // Stored in ms., sent/received in sec. Convert to seconds.
              json.put(REFRESH_LIFETIME, client.getRtLifetime() / 1000);
          } else {
              if(!isGet) {
                  json.put(REFRESH_LIFETIME, 0L);
              }// otherwise, omit in get if 0.
          }
          if (0 < client.getAtLifetime()) {
              // Stored in ms., sent/received in sec. Convert to seconds.
              json.put(ACCESS_TOKEN_LIFETIME, client.getAtLifetime() / 1000);
          } else {
              json.put(ACCESS_TOKEN_LIFETIME, 0L);
          }
          if (client.hasJWKS()) {
              json.put(JWKS, JSONWebKeyUtil.toJSON(client.getJWKS()));
          }
          if (client.hasJWKSURI()) {
              json.put(JWKS_URI, client.getJwksURI().toString());
          }
          JSONArray scopes = new JSONArray();
          scopes.addAll(client.getScopes());
          json.put(OA2Constants.SCOPE, scopes);
          json.put(OIDCCMConstants.CLIENT_URI, client.getHomeUri());
          json.put(OA2Constants.ERROR_URI, client.getErrorUri());
          // CIL-931 fix.
          json.put(STRICT_SCOPES, client.useStrictScopes());
          json.put(SKIP_SERVER_SCRIPTS, client.isSkipServerScripts());
          // Note that a contact email is something specific to OA4MP and does not occur in
          // either RFC 7591 or 7592.
          // CIL-1221
          json.put(PROXY_CLAIMS_LIST, client.getProxyClaimsList());
          json.put(FORWARD_REQUEST_SCOPES_TO_PROXY, client.isForwardScopesToProxy());
          json.put(PROXY_REQUEST_SCOPES, client.getProxyRequestScopes());
          json.put(IS_SERVICE_CLIENT, client.isServiceClient());
          JSONArray array = new JSONArray();
          array.addAll(client.getServiceClientUsers());
          json.put(SERVICE_CLIENT_USERS, array);
          json.put("email", client.getEmail());
          OA2ClientKeys clientKeys = (OA2ClientKeys) getOA2SE().getClientStore().getMapConverter().getKeys();
          json.put(clientKeys.extendsProvisioners(), client.isExtendsProvisioners());
          json.put(clientKeys.ersatzClient(), client.isErsatzClient());
          json.put(clientKeys.ersatzInheritIDToken(), client.isErsatzInheritIDToken());
          //CIL-1321 inheritance
          if (client.hasPrototypes()) {
              JSONArray jsonArray = new JSONArray();
              for (Identifier id : client.getPrototypes()) {
                  jsonArray.add(id.toString());
              }
              json.put(clientKeys.prototypes(), jsonArray);
          }
          // This is in seconds since the epoch
          json.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, client.getCreationTS().getTime() / 1000);
          if (client.getConfig() != null && !client.getConfig().isEmpty()) {

              json.put("cfg", client.getConfig());
          }
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

    public static String getDefaultAPIVersion() {
        return defaultAPIVersion;
    }

    public static void setDefaultAPIVersion(String defaultAPIVersion) {
        OIDCCMServlet.defaultAPIVersion = defaultAPIVersion;
    }

    static String defaultAPIVersion = API_VERSION_LATEST;

    /**
     * Used in serializing the client to JSON. lifetime that are positive
     * are divided by 1000 to convert from milliseconds to seconds.<br/><br/>
     * If they are non-positive, however, they are returned as is since negative values
     * are overloaded.
     *
     * @param lifetime
     * @return
     */
    protected long lifetimeToSec(long lifetime) {
        if (0 < lifetime) {
            return lifetime / 1000;
        } else {
            return lifetime;
        }
    }

    protected long lifetimeFromSec(long lifetime) {
        if (0 < lifetime) {
            return lifetime * 1000;
        } else {
            return lifetime;
        }
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
        String version = getVersion(getOA2SE().getCmConfigs().getRFC7592Config(), req);


        try {
            if (!(getOA2SE().getCmConfigs().hasRFC7592Config() && getOA2SE().getCmConfigs().getRFC7592Config().enabled) && getOA2SE().getCmConfigs().isEnabled()) {
                throw new IllegalAccessError("RFC 7592 not supported on this server. Request rejected.");
            }

            AdminClient adminClient = getAndCheckAdminClient(req);
            MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(adminClient);
            String rawID = req.getParameter(OA2Constants.CLIENT_ID);
            debugger.trace(this, "Starting delete request for admin client " + adminClient.getIdentifierString() + "\n" +
                    "for client id =\"" + rawID + "\"");
            if (rawID == null || rawID.isEmpty()) {
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST, "Missing client id", HttpStatus.SC_BAD_REQUEST, null, adminClient);
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
                // Never an anonymous client for a delete
                fireMessage(false, getOA2SE(), defaultReplacements(req, adminClient, client));
            }
            return;
        } catch (Throwable t) {
            handleException(new ExceptionHandlerThingie(t, req, resp));
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
            throw new OA2JSONException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "unknown client",
                    HttpStatus.SC_UNAUTHORIZED, // as per spec
                    null, adminClient
            );
        }
        // now we check that this admin owns this client
        List<Identifier> clientList = getOA2SE().getPermissionStore().getClients(adminClient.getIdentifier());
        if (!clientList.contains(client.getIdentifier())) {
            throw new OA2JSONException(OA2Errors.ACCESS_DENIED,
                    "access denied",
                    HttpStatus.SC_FORBIDDEN, // as per spec.
                    null, adminClient
            );
        }
    }

    protected String getVersion(CMConfig cmConfig, HttpServletRequest req){
         if(null != req.getParameter(API_VERSION_KEY)){
             return req.getParameter(API_VERSION_KEY);
         }
         String requestUri = req.getRequestURI();
         String endpoint = cmConfig.getEndpoint();
         if(StringUtils.isTrivial(endpoint)){
             throw new NFWException("the endpoint for the " + cmConfig.protocol + " has not been configured.");
         }
         if(requestUri.endsWith("/")){
             requestUri = requestUri.substring(0,requestUri.length()-1); // normalize. remove trailing /
         }
         // No component means send back "none" so the endpoint can resolve what to do.
        // Note the fact that we are here in the first place is because
        // they sent a proper request to Tomcat, so we know that the endpoint (e.g. oidc-cm) is in the URI.
         if(requestUri.endsWith("/"+endpoint)) return API_VERSION_NONE;
         // by this point, it ends with /version
         String version= requestUri.substring(1+requestUri.lastIndexOf("/")); // return exactly API
         return version;
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
        AdminClient adminClient = null;
        OA2Client client = null;
        String version = getVersion(getOA2SE().getCmConfigs().getRFC7592Config(), req);

        try {
            if (!(getOA2SE().getCmConfigs().hasRFC7592Config() && getOA2SE().getCmConfigs().getRFC7592Config().enabled) && getOA2SE().getCmConfigs().isEnabled()) {
                throw new IllegalAccessError("RFC 7592 not supported on this server. Request rejected.");
            }

            adminClient = getAndCheckAdminClient(req);
            MetaDebugUtil adminDebugger = MyProxyDelegationServlet.createDebugger(adminClient);
            if (adminDebugger.getDebugLevel() == MetaDebugUtil.DEBUG_LEVEL_TRACE) {
                printAllParameters(req);

            }
            JSON rawJSON = getPayload(req, adminDebugger);
            if (rawJSON.isArray()) {
                adminDebugger.info(this, "Got a JSON array rather than a request:" + rawJSON);
                throw new IllegalArgumentException("incorrect argument. Not a valid JSON request");
            }
            JSONObject jsonRequest = (JSONObject) rawJSON;
            // can send the client id as either a parameter or in the JSON blob.
            if (jsonRequest.containsKey(OA2Constants.CLIENT_ID)) {
                client = (OA2Client) getOA2SE().getClientStore().get(BasicIdentifier.newID(jsonRequest.getString(OA2Constants.CLIENT_ID)));
            } else {
                client = getClient(req);
            }
            if (client == null) {
                throw new OA2JSONException(OA2Errors.UNAUTHORIZED_CLIENT,
                        "unknown client",
                        HttpStatus.SC_BAD_REQUEST,
                        null, adminClient);

            }
            checkAdminPermission(adminClient, client);

            adminDebugger.trace(this, rawJSON.toString());

            if (jsonRequest.size() == 0) {
                // Playing nice here. If they upload an empty object, the net effect is going to be to zero out
                // everything for this client except the id. The assumption is they don't want to do that.
                adminDebugger.info(this, "Got an empty JSON object. Request rejected.");
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST,
                        "invalid request",
                        HttpStatus.SC_BAD_REQUEST,
                        null, adminClient);
            }
            //have to check that certain key/values are excluded from the update.
            if (jsonRequest.containsKey(OIDCCMConstants.REGISTRATION_ACCESS_TOKEN) ||
                    jsonRequest.containsKey(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT) ||
                    jsonRequest.containsKey(OIDCCMConstants.CLIENT_ID_ISSUED_AT)) {
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST,
                        "invalid parameter",
                        HttpStatus.SC_BAD_REQUEST,
                        null, client);
            }
            if (jsonRequest.containsKey(OA2Constants.SCOPE)) {
                // the only thing that we are concerned with  is client is attempting to increase their
                // scopes. These are permitted to reduce them.
                boolean rejectRequest = false;
                JSONArray newScopes = toJA(jsonRequest, OA2Constants.SCOPE);
                Collection<String> oldScopes = client.getScopes();
                // Fix for CIL-775
                if (client.isPublicClient()) {
                    if (oldScopes.size() == 1 && oldScopes.contains(OA2Scopes.SCOPE_OPENID)) {
                        // This is a public client. they are allowed to re-assert it
                        if (!(newScopes.size() == 1 && newScopes.contains(OA2Scopes.SCOPE_OPENID))) {
                            throw new OA2JSONException(OA2Errors.INVALID_REQUEST,
                                    "Cannot increase scope of public client.",
                                    HttpStatus.SC_BAD_REQUEST,
                                    null, client);
                        }
                    }

                }
                Collection<String> newScopeList = new HashSet<>();
                // Fix for CIL-725 Allow admin clients to alter scopes as desired.
                // NOTE as long as this admin-only access this is ok. Otherwise the
                // previous version the only permits a reduction in scopes is allowed.
                // We do reject a scope if it is not on the supported list for this server
                Collection<String> supportedScopes = getOA2SE().getScopes();
                String scope = null;
                for (Object x : newScopes) {
                    scope = x.toString();
                    if (!supportedScopes.contains(scope)) {
                        // then this is not in the list, request is rejected
                        rejectRequest = true;
                        adminDebugger.trace(this, "rejected scope '" + scope + "', not on list of server supported scopes:" + supportedScopes);
                        break;
                    }
                    newScopeList.add(scope);
                }
                if (rejectRequest) {
                    throw new OA2JSONException(OA2Errors.INVALID_SCOPE,
                            "invalid scope",
                            HttpStatus.SC_FORBIDDEN, // as per spec, section RFC 7592 section 2.2
                            null, client
                    );
                }
                client.setScopes(newScopeList);
            }
            boolean isDebugOn = client.isDebugOn(); // CIL-1538

            // so we create a new client, set the secret and id, then update that. This way if
            // this fails we can just back out.
            OA2Client newClient = (OA2Client) getOA2SE().getClientStore().create();
            boolean generateNewSecret = false;

            if (jsonRequest.containsKey(CLIENT_SECRET)) {
                // then we have to check this is a valid client. If this is missing, then
                // we are being requested to generate a new secret.
                String hashedSecret = DigestUtils.sha1Hex(jsonRequest.getString(CLIENT_SECRET));
                if (!hashedSecret.equals(client.getSecret())) {
                    throw new OA2JSONException(OA2Errors.INVALID_REQUEST,
                            "client id does not match",
                            HttpStatus.SC_FORBIDDEN,
                            null, client);
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

                newClient = updateClient(newClient, adminClient, false, jsonRequest, false, version);
                if (adminClient.isDebugOn()) {
                    // CIL-607
                    // Never an anonymous client for a put.
                    fireMessage(false, getOA2SE(), defaultReplacements(req, adminClient, newClient));
                }
                newClient.setDebugOn(isDebugOn); // CIL-1538
                getOA2SE().getClientStore().save(newClient);
                writeOK(resp, toJSONObject(newClient, version, false));
                //     writeOK(resp, resp);

            } catch (Throwable t) {
                // back out of it
                warn("Error attempting to update client \"" + client.getIdentifierString() + "\". " +
                        "Message = \"" + t.getMessage() + "\". Request is rejected");
                // resp.setStatus(HttpStatus.SC_BAD_REQUEST);
                handleException(new OA2ExceptionHandlerThingie(t, req, resp, (client == null ? adminClient : client)));
            }
        } catch (Throwable t) {
            handleException(new OA2ExceptionHandlerThingie(t, req, resp, (client == null ? adminClient : client)));
        }
    }

    @Override
    public void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {


        try {
            if (!(getOA2SE().getCmConfigs().hasRFC7591Config() && getOA2SE().getCmConfigs().getRFC7591Config().enabled) && getOA2SE().getCmConfigs().isEnabled()) {
                throw new IllegalAccessError("RFC 7591 not supported on this server. Request rejected.");
            }
            // The super class rejects anything that does not have an encoding type of
            // application/x-www-form-urlencoded
            // We want this servlet to understand only application/json, so we
            // test for that instead.

            //   printAllParameters(httpServletRequest);
            if (doPing(httpServletRequest, httpServletResponse)) return;
            DebugUtil.trace(this, "ENCODING is of type " + httpServletRequest.getContentType());
            // TODO Probably should parse the encoding type. 'application/json; charset=UTF-8' would be standard.
            if (!httpServletRequest.getContentType().contains("application/json")) {
                // Fixes CIL-1852
                httpServletResponse.setStatus(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE);
                httpServletResponse.setContentType("application/json");
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("error", "unsupported encoding");
                // Fix https://github.com/ncsa/oa4mp/issues/133 as issue 3.1.3.1 in AAF report
                getMyLogger().info("Unsupported encoding of \"" + httpServletRequest.getContentType() + " for body of POST. Request rejected.");
                jsonObject.put("description", "Unsupported encoding for body of POST. Request rejected.");
                httpServletResponse.getWriter().println(jsonObject);
                httpServletResponse.getWriter().flush();
                return;
            }
            // delegates to the doIt method.
            doIt(httpServletRequest, httpServletResponse);
        } catch (Throwable t) {
            handleException(new ExceptionHandlerThingie(t, httpServletRequest, httpServletResponse));
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
        String[] credentials = OA2HeaderUtils.getCredentialsFromHeaders(request, "Bearer");
        // need to verify that this is an admin client.
        Identifier acID = BasicIdentifier.newID(credentials[OA2HeaderUtils.ID_INDEX]);
        if (!getOA2SE().getAdminClientStore().containsKey(acID)) {
            throw new UnknownClientException("the given id of \"" + acID + "\" is not recognized as an admin client.");
        }
        AdminClient adminClient = getOA2SE().getAdminClientStore().get(acID);
        MetaDebugUtil adminDebugger = MyProxyDelegationServlet.createDebugger(adminClient);
        String adminSecret = credentials[OA2HeaderUtils.SECRET_INDEX];
        if (adminSecret == null || adminSecret.isEmpty()) {
            throw new WrongPasswordException("missing secret.");
        }
        if (!getOA2SE().getClientApprovalStore().isApproved(acID)) {
            adminDebugger.trace(this, "Admin client \"" + acID + "\" is not approved.");
            throw new UnapprovedClientException("this admin client has not been approved.", null);
        }
        String hashedSecret = DigestUtils.sha1Hex(adminSecret);
        if (!adminClient.getSecret().equals(hashedSecret)) {
            adminDebugger.trace(this, "Admin client \"" + acID + "\" and secret do not match.");
            throw new WrongPasswordException("client and secret do not match");
        }
        return adminClient;
    }


    protected OA2Client getAndCheckOA2Client(HttpServletRequest request) throws Throwable {
        String[] credentials = OA2HeaderUtils.getCredentialsFromHeaders(request, "Bearer");
        // need to verify that this is an admin client.
        Identifier clientID = BasicIdentifier.newID(credentials[OA2HeaderUtils.ID_INDEX]);
        if (!getOA2SE().getClientStore().containsKey(clientID)) {
            throw new GeneralException("the given id of \"" + clientID + "\" is not recognized as a  client.");
        }
        OA2Client oa2Client = (OA2Client) getOA2SE().getClientStore().get(clientID);
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(oa2Client);
        String clientSecret = credentials[OA2HeaderUtils.SECRET_INDEX];
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new GeneralException("missing secret.");
        }
        if (!getOA2SE().getClientApprovalStore().isApproved(clientID)) {
            debugger.trace(this, "Client \"" + clientID + "\" is not approved.");
            throw new UnapprovedClientException("this client has not been approved.", oa2Client);
        }
        String hashedSecret = DigestUtils.sha1Hex(clientSecret);
        if (!oa2Client.getSecret().equals(hashedSecret)) {
            debugger.trace(this, "Client \"" + clientID + "\" and secret do not match.");
            throw new GeneralException("client and secret do not match");
        }
        return oa2Client;
    }

    PermissionServer permissionServer = null;

    /*
    Note that this is only called in the doPost method.
     */
    @Override

    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        try {
            doIt2(httpServletRequest, httpServletResponse);
        } catch (Throwable t) {
            handleException(new ExceptionHandlerThingie(t, httpServletRequest, httpServletResponse));
        }
    }

    /**
     * The workhorse method for POST.
     * @param httpServletRequest
     * @param httpServletResponse
     * @throws Throwable
     */
    protected void doIt2(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        if (!getOA2SE().getCmConfigs().isEnabled()) {
            throw new ServletException("unsupported service");
        }
        String version = getVersion(getOA2SE().getCmConfigs().getRFC7591Config(), httpServletRequest);

        CM7591Config cm7591Config = getOA2SE().getCmConfigs().getRFC7591Config();
        boolean isAnonymous = false;
        String host = httpServletRequest.getRemoteHost();
        AdminClient adminClient = null;
        try {
            adminClient = getAndCheckAdminClient(httpServletRequest);
            // https://github.com/ncsa/oa4mp/issues/117 separate out the exceptions, don't just try to process them
            // all at once and fail.
        } catch (IllegalArgumentException ge) {

            if (!cm7591Config.anonymousOK) {
                DebugUtil.trace(this, "anonymous mode not enabled, exception thrown.");
                throw ge;
            }
            if (!cm7591Config.checkAnonymousDomain(host)) {
                throw new GeneralException("Anonymous client access restricted for domain " + host + ".");
            }
            DebugUtil.trace(this, "anonymous ok");
            isAnonymous = true;
        } catch (UnknownClientException | WrongPasswordException | UnapprovedClientException zzz) {
            throw new GeneralException("Bad admin client " + host + ":" + zzz.getMessage());
        }

        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(adminClient);
        if (debugger.getDebugLevel() == MetaDebugUtil.DEBUG_LEVEL_TRACE) {
            printAllParameters(httpServletRequest);
        }
        debugger.trace(this, "Starting to process " + httpServletRequest.getMethod());
        // Now that we have the admin client (so we can do this request), we read the payload:
        JSON rawJSON = getPayload(httpServletRequest, debugger);

        if ((!isAnonymous) && adminClient.getMaxClients() < getOA2SE().getPermissionStore().getClientCount(adminClient.getIdentifier())) {
            debugger.info(this, " Max client count of " + adminClient.getMaxClients() + " exceeded.");
            throw new GeneralException("Max client count of " + adminClient.getMaxClients() + " exceeded.");
        }
        debugger.trace(this, rawJSON.toString());
        if (rawJSON.isArray()) {
            debugger.info(this, " Got a JSON array rather than a request:" + rawJSON);
            throw new IllegalArgumentException("incorrect argument. Not a valid JSON request");
        }
        JSONObject jsonRequest = (JSONObject) rawJSON; // now we know it is a JSON Object
        OA2Client template = null;
        template = (OA2Client) getOA2SE().getClientStore().create();
        if (cm7591Config.template != null) {
            Identifier newID = template.getIdentifier();
            Date createTS = template.getCreationTS();
            template = (OA2Client) getOA2SE().getClientStore().get(cm7591Config.template);
            template.setIdentifier(newID);
            template.setCreationTS(createTS);
        }
        // https://github.com/ncsa/oa4mp/pull/85 -- clients (such as a few in GoLang) that upload scopes as
        // strings expect them back as strings, not JSON arrays. Return them in the format sent.
        boolean returnStringScopes = false;
        try {
            jsonRequest.getJSONArray(SCOPE);
            returnStringScopes = false;
        } catch (JSONException jse) {
            returnStringScopes = true;
        }

        OA2Client newClient = processRegistrationRequest(jsonRequest, adminClient, isAnonymous, template, version);
        if (isAnonymous) {
            // All anonymous requests send a notification.
            fireMessage(isAnonymous, getOA2SE(), defaultReplacements(httpServletRequest, adminClient, newClient));
        } else {
            if (adminClient.isDebugOn()) {
                // CIL-607
                fireMessage(false, getOA2SE(), defaultReplacements(httpServletRequest, adminClient, newClient));
            }
        }

        JSONObject jsonResp = new JSONObject(); // The response object.
        String newID = newClient.getIdentifierString(); // default, random id with default configured head.
        // CIL-1671
        if (jsonRequest.containsKey(CLIENT_ID)) {
            if (adminClient != null && adminClient.isAllowCustomIDs()) {
                newID = jsonRequest.getString(CLIENT_ID);
            }
        } else {
            // other case is that there is no explicit request, but the admin wants
            // us to generate the ids.
            if (adminClient != null && adminClient.isAllowCustomIDs() && adminClient.isGenerateIDs()) {
                if (adminClient.getIdHead() == null) {
                    // at this point, not setting still results in a random client ID
                    warn(adminClient.getIdentifierString() + " requested generate client id but there is no id head set");
                } else {
                    byte[] u = new byte[16];
                    secureRandom.nextBytes(u);
                    BigInteger bi = new BigInteger(u);
                    bi = bi.abs(); // since negative random integers occur.
                    String uniquePart = bi.toString(16);
                    if (adminClient.isUseTimestampInIDs()) {
                        uniquePart = uniquePart + "/" + System.currentTimeMillis();
                    }
                    newID = adminClient.getIdHead().toString();
                    newID = newID + (newID.endsWith("/") ? "" : "/") + uniquePart;
                }
            }
        }
        newClient.setIdentifier(BasicIdentifier.newID(newID));
        jsonResp.put(CLIENT_ID, newID);
        if (!StringUtils.isTrivial(newClient.getSecret())) {

            jsonResp.put(CLIENT_SECRET, newClient.getSecret());
            String hashedSecret = DigestUtils.sha1Hex(newClient.getSecret());
            // Now make a hash of the secret and store it.
            jsonResp.put(OIDCCMConstants.CLIENT_ID_ISSUED_AT, newClient.getCreationTS().getTime() / 1000);
            String secret = DigestUtils.sha1Hex(newClient.getSecret());
            newClient.setSecret(secret);
            jsonResp.put(OIDCCMConstants.CLIENT_SECRET_EXPIRES_AT, 0L);

        }
        String registrationURI = getOA2SE().getCmConfigs().getRFC7591Config().uri.toString();
        // Next, we have to construct the registration URI by adding in the client ID.
        // Spec says we can add parameters here, but not elsewhere.
        jsonResp.put(OIDCCMConstants.REGISTRATION_CLIENT_URI, registrationURI + "?" + OA2Constants.CLIENT_ID + "=" + newClient.getIdentifierString());
        // oidc-client expects the scopes which we may return.
        if (returnStringScopes) {
            jsonResp.put(SCOPE, String.join(" ", newClient.getScopes()));
        } else {
            JSONArray xxx = new JSONArray();
            xxx.addAll(newClient.getScopes());
            jsonResp.put(SCOPE, xxx);
        }
        switch (version){
            case API_VERSION_NONE:
            case API_VERSION_5_4:
                // do not set anything
                break;
            default:
                newClient.getOIDC_CM_Attributes().put(API_VERSION_KEY, version);
        }
        debugger.trace(this, "saving this client");
        getOA2SE().getClientStore().save(newClient);

        // this adds the client to the list of clients managed by the admin
        if (!isAnonymous) {
            debugger.trace(this, "Adding permissions for client " + newClient.getIdentifierString());
            AddClientRequest addClientRequest = new AddClientRequest(adminClient, newClient);
            getPermissionServer().addClient(addClientRequest);
        }
        // Finally, approve it since it was created with and admin client, which is assumed to be trusted

        debugger.trace(this, "Setting approval record for client " + newClient.getIdentifierString());
        ClientApproval approval = new ClientApproval(newClient.getIdentifier());
        approval.setApprovalTimestamp(new Date());
        // https://github.com/ncsa/oa4mp/pull/81
        if (isAnonymous) {
            if (cm7591Config.autoApprove && cm7591Config.checkAutoApproveDomain(host)) {
                approval.setApprover(cm7591Config.autoApproverName);
                approval.setApproved(true);
                approval.setStatus(ClientApproval.Status.APPROVED);
            } else {
                approval.setApproved(false);
                approval.setStatus(ClientApproval.Status.PENDING);
            }
        } else {
            approval.setApprover(adminClient.getIdentifierString());
            approval.setApproved(true);
            approval.setStatus(ClientApproval.Status.APPROVED);
        }
        getOA2SE().getClientApprovalStore().save(approval);
        // Github 84 https://github.com/ncsa/oa4mp/issues/84
        // Also this is CIL-1597
        writeCreateOK(httpServletResponse, jsonResp);
        logOK(httpServletRequest); // CIL-1722

        //  writeOK(httpServletResponse, jsonResp);
    }


    protected SecureRandom secureRandom = new SecureRandom();

    private void writeOK(HttpServletResponse httpServletResponse, JSON resp) throws IOException {
        httpServletResponse.setStatus(HttpStatus.SC_OK);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().println(resp.toString());
        httpServletResponse.getWriter().flush(); // commit it
    }

    private void writeCreateOK(HttpServletResponse httpServletResponse, JSON resp) throws IOException {
        // write first since after flush(), no updates work and the status is set as SC_OK, regardless.
        httpServletResponse.setStatus(HttpStatus.SC_CREATED);
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().println(resp.toString());
        httpServletResponse.getWriter().flush(); // commit it
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
            throw new IllegalArgumentException("There is no content for this request");
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
                                     boolean isAnonymous,
                                     JSONObject jsonRequest,
                                     boolean newClient,
                                     String version) {
        OA2ClientKeys keys = new OA2ClientKeys();

        /*
        NOTE that this will check for required attributes, process them, then remove them from the JSON.
        This allows us to store the non-essential parameters in the request. At this point we keep
        them in case we need them, but we are not going to allocate actual storage for them, just folding them
        into the extra attributes of the client's configuration.
         */

        if (jsonRequest.containsKey(OIDCCMConstants.APPLICATION_TYPE)) {
            // optional but must be "web" if present
            if (!jsonRequest.getString(OIDCCMConstants.APPLICATION_TYPE).equals("web")) {
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST,
                        "Unsupported application type",
                        HttpStatus.SC_BAD_REQUEST,
                        null, client);
            }
        }

        jsonRequest.remove(OIDCCMConstants.APPLICATION_TYPE);
        handleGrants(client, jsonRequest, keys);
        handleResponseTypes(client, jsonRequest, keys);
        JSONArray redirectURIs = null;  // spec says it is a JSON array
        if (jsonRequest.containsKey(OIDCCMConstants.REDIRECT_URIS)) {
            redirectURIs = toJSONArray(jsonRequest, OIDCCMConstants.REDIRECT_URIS, client);
            // URI sanity check. Since it's JSON they could send garbage.
            // Wildcard check for CIL-871
            for (Object z : redirectURIs) {
                if (!(z instanceof String)) {
                    throw new OA2JSONException(
                            OA2Errors.INVALID_REQUEST,
                            " illegal redirect uri \"" + z + "\" ",
                            HttpStatus.SC_BAD_REQUEST,
                            null, client);
                }
                if (z.toString().contains("*")) {
                    throw new OA2JSONException(
                            OA2Errors.INVALID_REQUEST,
                            "wildcards not allows in redirect uri \"" + z + "\" ",
                            HttpStatus.SC_BAD_REQUEST, null, client);
                }
            }
            client.setCallbackURIs(redirectURIs);
            jsonRequest.remove(OIDCCMConstants.REDIRECT_URIS);
        }
        // Now we do the stuff we think we need.
        if (!jsonRequest.containsKey(OIDCCMConstants.CLIENT_NAME)) {
            throw new OA2JSONException(
                    OA2Errors.INVALID_REQUEST,
                    "no client name",
                    HttpStatus.SC_BAD_REQUEST,
                    null, client);
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
        //CIL-1321
        OA2ClientKeys clientKeys = (OA2ClientKeys) getOA2SE().getClientStore().getMapConverter().getKeys();


        if (jsonRequest.containsKey(TOKEN_ENDPOINT_AUTH_METHOD)) {
            // not required, but if present, we support exactly three nontrivial options.
            String authMethod = jsonRequest.getString(TOKEN_ENDPOINT_AUTH_METHOD);
            boolean gotSupportedAuthMethod = false;
            switch (authMethod) {
                case OA2Constants.TOKEN_ENDPOINT_AUTH_NONE:
                    if (newClient) {
                        gotSupportedAuthMethod = true;
                        client.setPublicClient(true);

                    } else {
                        if (client.isPublicClient()) {
                            // CIL-884.
                            // do nothing -- let them udpdate everything else but
                            // their confidentiality status.
                            gotSupportedAuthMethod = true;

                        } else {
                            // Don't let admins change client confidential --> public
                            throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                                    "cannot change from a confidential to a public client",
                                    HttpStatus.SC_BAD_REQUEST, null, client);

                        }
                    }
                    break;
                case TOKEN_ENDPOINT_AUTH_BASIC:
                case TOKEN_ENDPOINT_AUTH_POST:
                    if (!newClient && client.isPublicClient()) {
                        // Only if this is already true do we throw an exception.
                        // This means it was public (=no secret) and now they want
                        // a secret.  We don't re-issue secrets. They have to register a new client
                        // to get a secret.
                        throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                                "cannot change from a public to a confidential client",
                                HttpStatus.SC_BAD_REQUEST, null, client);

                    }
                    gotSupportedAuthMethod = true;
                    client.setPublicClient(false);
                    client.setSignTokens(true); // always for us.
                    break;
                case TOKEN_ENDPOINT_AUTH_PRIVATE_KEY:
                    // either they supply us with the keys or a URI that points to them
                    if (jsonRequest.containsKey(JWKS_URI)) {
                        client.setJwksURI(URI.create(jsonRequest.getString(JWKS_URI)));
                        jsonRequest.remove(JWKS_URI);
                        client.setServiceClient(true);
                        gotSupportedAuthMethod = true;
                    }
                    if (jsonRequest.containsKey(JWKS)) {
                        client.setSecret(null);
                        client.setJWKS(getJwkUtil().fromJSON(jsonRequest.getJSONObject(JWKS)));
                        jsonRequest.remove(JWKS);
                        client.setServiceClient(true);
                        gotSupportedAuthMethod = true;
                    }
                    break;
                default:
                    gotSupportedAuthMethod = false;
            }
            if (!gotSupportedAuthMethod) {
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                        "unsupported token endpoint authorization method \"" + authMethod + "\"",
                        HttpStatus.SC_BAD_REQUEST, null, client);
            }
            jsonRequest.remove(TOKEN_ENDPOINT_AUTH_METHOD);
        }
        if (!jsonRequest.containsKey(OA2Constants.SCOPE)) {
            client.setScopes(new ArrayList<>()); // zeros it out
            // NOTE We no longer require that a client set scopes. If the server is OIDC aware
            // then that should just mean it accepts the openid scope and if missing
            // does not return much (like no subject or id token), For some clients
            // that just want an access token, that is fine.
        } else {
            JSONArray newScopes = toJA(jsonRequest, OA2Constants.SCOPE);
            // issue is that some client registrations can send along redundant scopes
            // and may send along things like offline access, e.g. ["openid","openid","offline_access"]
            //  Fix for CIL-1159
            HashSet<String> unique = new HashSet<>();
            unique.addAll(newScopes);

            if (client.isPublicClient()) {
                // public clients cannot reset their scopes ever.
                // They must, however, send along a single openid scope or this gets flagged as an error
                if (!unique.contains(OA2Scopes.SCOPE_OPENID)) {
                    throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                            "cannot decrease scope on a public client.",
                            HttpStatus.SC_BAD_REQUEST, null, client);
                }
                if (1 < newScopes.size()) {
                    if (!unique.contains(OA2Scopes.SCOPE_OFFLINE_ACCESS)) {
                        throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                                "cannot increase scopes on a public client.",
                                HttpStatus.SC_BAD_REQUEST, null, client);
                    }
                }
            }
            newScopes.clear();
            newScopes.addAll(unique);
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
            // Todo: Really check these and allow for multiple values
            // Todo: This takes only the very first.
            JSONArray emails = toJA(jsonRequest, OIDCCMConstants.CONTACTS);
            if (1 < emails.size()) {
                ServletDebugUtil.info(this, "Multiple contacts addresses found " + emails + "\n Only the first is used currently.");
            }
            if (!emails.isEmpty()) {
                client.setEmail(emails.getString(0));
            }
            jsonRequest.remove(OIDCCMConstants.CONTACTS);
        }


        //CIL-703

        if (jsonRequest.containsKey("cfg")) {
            if (client.isPublicClient()) {
                throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                        "custom configurations not permitted in public clients.",
                        HttpStatus.SC_BAD_REQUEST, null, client);

            }
            JSONObject jsonObject = jsonRequest.getJSONObject("cfg");

            // CIL-889 fix
            if (isAnonymous) {
                if (jsonRequest.getString("cfg").toLowerCase().contains("qdl")) {
                    // Pretty draconian test -- any tag for QDL gets booted.
                    throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                            "QDL scripting is not allowed for this client.",
                            HttpStatus.SC_BAD_REQUEST, null, client);
                }
            }
            if (adminClient.isAllowQDL()) {
                // CIL-1031
                if (adminClient.allowQDLCodeBlocks()) {
                    if (jsonRequest.getString("cfg").contains("qdl") && jsonRequest.getString("cfg").contains("qdl")) {
                        if (jsonRequest.getString("cfg").contains("\"code\"")) {
                            throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                                    "QDL code blocks are not allowed for this client.",
                                    HttpStatus.SC_BAD_REQUEST, null, client);
                        }
                    }
                }
            } else {
                if (jsonRequest.getString("cfg").toLowerCase().contains("qdl")) {
                    // Pretty draconian test -- any tag for QDL gets booted.
                    throw new OA2JSONException(OA2Errors.INVALID_REQUEST_OBJECT,
                            "QDL scripting is not allowed for this client.",
                            HttpStatus.SC_BAD_REQUEST, null, client);
                }
            }
            jsonRequest.remove("cfg");
            client.setConfig(jsonObject);
        } else {
            // CIL-735 if no config object, remove it.
            if (!newClient) {
                client.setConfig(null);
            }
        }

        if (jsonRequest.containsKey(REFRESH_LIFETIME)) {
            // NOTE this is sent in seconds but is recorded as ms., so convert to milliseconds here.
            // If the value is <=0 then they are asking for the server default (-1) or disabling
            // refresh tokens (0).
            // It is possible to set up refresh token lifetimes by specifying the grant type of refresh_token,
            // but passing in this parameter overrides that.
            client.setRtLifetime(lifetimeFromParameter(jsonRequest.get(REFRESH_LIFETIME)));
            jsonRequest.remove(REFRESH_LIFETIME);
        } else {
            // Fix for https://github.com/ncsa/oa4mp/issues/176
            // always set new clients to default if not asserted.
            // if client already has this zero-ed and it is not asserted, ignore it.
            // Otherwise, it would make clients that don't want refresh tokens manage
            // refresh token lifetimes with every update.
            if (newClient) {
                client.setRtLifetime(getOA2SE().getCmConfigs().getRFC7591Config().getDefaultRefreshTokenLifetime());
            } else {
                client.setRtLifetime(getOA2SE().getCmConfigs().getRFC7592Config().getDefaultRefreshTokenLifetime());
            }
        }
        if (jsonRequest.containsKey(MAX_REFRESH_LIFETIME)) {
            client.setMaxRTLifetime(lifetimeFromParameter(jsonRequest.get(MAX_REFRESH_LIFETIME)));
            jsonRequest.remove(MAX_REFRESH_LIFETIME);
        }
        if (jsonRequest.containsKey(ACCESS_TOKEN_LIFETIME)) {
            client.setAtLifetime(lifetimeFromParameter(jsonRequest.get(ACCESS_TOKEN_LIFETIME)));
            jsonRequest.remove(ACCESS_TOKEN_LIFETIME);
        }
        if (jsonRequest.containsKey(MAX_ACCESS_TOKEN_LIFETIME)) {
            client.setMaxATLifetime(lifetimeFromParameter(jsonRequest.get(MAX_ACCESS_TOKEN_LIFETIME)));
            jsonRequest.remove(MAX_ACCESS_TOKEN_LIFETIME);
        }

        if (jsonRequest.containsKey(ID_TOKEN_LIFETIME)) {
            // NOTE this is sent in seconds but is recorded as ms., so convert to milliseconds here.
            client.setIdTokenLifetime(lifetimeFromParameter(jsonRequest.get(ID_TOKEN_LIFETIME)));
            jsonRequest.remove(ID_TOKEN_LIFETIME);
        }
        if (jsonRequest.containsKey(MAX_ID_TOKEN_LIFETIME)) {
            // NOTE this is sent in seconds but is recorded as ms., so convert to milliseconds here.
            client.setMaxIDTLifetime(lifetimeFromParameter(jsonRequest.get(MAX_ID_TOKEN_LIFETIME)));
            jsonRequest.remove(MAX_ID_TOKEN_LIFETIME);
        }

        // Remember that for updates (via PUT) there is no anonymous mode.
        if (!isAnonymous) {
            if (jsonRequest.containsKey(clientKeys.prototypes())) {
                JSONArray jsonArray = jsonRequest.getJSONArray(clientKeys.prototypes());
                List<Identifier> prototypes = new ArrayList<>();
                for (int i = 0; i < jsonArray.size(); i++) {
                    prototypes.add(BasicIdentifier.newID(jsonArray.getString(i)));
                }
                client.setPrototypes(prototypes);
            }
            // Fix  https://github.com/ncsa/oa4mp/issues/159
            if (jsonRequest.containsKey(clientKeys.rtGracePeriod())) {
                client.setRtGracePeriod(lifetimeFromParameter(jsonRequest.get(clientKeys.rtGracePeriod())));
            } else {
                // if missing, set it to use whatever the server default is.
                client.setRtGracePeriod(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT);
            }
            if (jsonRequest.containsKey(clientKeys.extendsProvisioners())) {
                client.setExtendsProvisioners(jsonRequest.getBoolean(clientKeys.extendsProvisioners()));
            }
            if (jsonRequest.containsKey(clientKeys.ersatzClient())) {
                client.setErsatzClient(jsonRequest.getBoolean(clientKeys.ersatzClient()));
            }
            if (jsonRequest.containsKey(clientKeys.ersatzInheritIDToken())) {
                client.setErsatzInheritIDToken(jsonRequest.getBoolean(clientKeys.ersatzInheritIDToken()));
            }
            if (jsonRequest.containsKey(EA_SUPPORT)) {
                client.setExtendedAttributeSupport(jsonRequest.getBoolean(EA_SUPPORT));
            }
            if (jsonRequest.containsKey(ERSATZ_CLIENT_PROVISIONERS)) {
                JSONArray array;
                try {
                    array = jsonRequest.getJSONArray(ERSATZ_CLIENT_PROVISIONERS);
                } catch (Throwable t) {
                    array = new JSONArray();
                    array.add(jsonRequest.getString(ERSATZ_CLIENT_PROVISIONERS));
                }
                Identifier provisionerID = BasicIdentifier.newID(array.getString(0));
                Permission permission = getOA2SE().getPermissionStore().getErsatzChain(
                        adminClient.getIdentifier(),
                        provisionerID,
                        client.getIdentifier());
                if (permission == null) {
                    // new clients this is null, but it may exist from a previous attempt.
                    permission = getOA2SE().getPermissionStore().create();
                    permission.setSubstitute(true);
                    permission.setAdminID(adminClient.getIdentifier());
                    permission.setClientID(provisionerID);
                    permission.setErsatzChain(array);
                } else {
                    // check that this has the right information, so treat this as an update
                    permission.setErsatzChain(array);
                }
                getOA2SE().getPermissionStore().save(permission);
            }
            if (jsonRequest.containsKey(STRICT_SCOPES)) {
                client.setStrictscopes(jsonRequest.getBoolean(STRICT_SCOPES));
                jsonRequest.remove(STRICT_SCOPES);
            }
            if (jsonRequest.containsKey(SKIP_SERVER_SCRIPTS)) {
                client.setSkipServerScripts(jsonRequest.getBoolean(SKIP_SERVER_SCRIPTS));
                jsonRequest.remove(SKIP_SERVER_SCRIPTS);
            }
            // CIL-1221
            if (jsonRequest.containsKey(PROXY_CLAIMS_LIST)) {
                client.setProxyClaimsList(toJSONArray(jsonRequest, PROXY_CLAIMS_LIST, client));
                //client.setProxyClaimsList(jsonRequest.getJSONArray(PROXY_CLAIMS_LIST));
                jsonRequest.remove(PROXY_CLAIMS_LIST);
            }
            if (jsonRequest.containsKey(FORWARD_REQUEST_SCOPES_TO_PROXY)) {
                client.setForwardScopesToProxy(jsonRequest.getBoolean(FORWARD_REQUEST_SCOPES_TO_PROXY));
                jsonRequest.remove(FORWARD_REQUEST_SCOPES_TO_PROXY);
            }
            if (jsonRequest.containsKey(PROXY_REQUEST_SCOPES)) {
                client.setProxyRequestScopes(toJSONArray(jsonRequest, PROXY_REQUEST_SCOPES, client));
                jsonRequest.remove(PROXY_REQUEST_SCOPES);
            }
            if (jsonRequest.containsKey(IS_SERVICE_CLIENT)) {
                client.setServiceClient(jsonRequest.getBoolean(IS_SERVICE_CLIENT));
                jsonRequest.remove(IS_SERVICE_CLIENT);
            }
            if (jsonRequest.containsKey(SERVICE_CLIENT_USERS)) {
                client.setServiceClientUsers(toJSONArray(jsonRequest, SERVICE_CLIENT_USERS, client));
                jsonRequest.remove(SERVICE_CLIENT_USERS);
            }

        }
        if (jsonRequest.containsKey(DESCRIPTION)) {
            client.setDescription(jsonRequest.getString(DESCRIPTION));
            jsonRequest.remove(DESCRIPTION);
        }
        // Fix for CIL-734: now handle everything else left over
        client.removeOIDC_CM_Attributes();
        if (!jsonRequest.isEmpty()) {
            client.setOIDC_CM_attributes(jsonRequest);
        }
        return client;

    }

    /**
     * So clients can send strings of values with units, e.g. "1 month". OA4MP supports this for its
     * own values.
     *
     * @param raw
     * @return
     */
    protected long lifetimeFromParameter(Object raw) {
        if (raw instanceof Integer) {
            return lifetimeFromSec((Integer) raw);
        }
        if (raw instanceof Long) {
            return lifetimeFromSec((Long) raw);
        }
        return XMLConfigUtil.getValueSecsOrMillis(raw.toString(), true);
    }

    protected JSONArray toJSONArray(JSONObject jsonRequest,
                                    String key,
                                    OA2Client client) {
        JSONArray array = null;
        if (jsonRequest.containsKey(key)) {
            Object object = jsonRequest.get(key);
            if (object instanceof JSONArray) {
                array = (JSONArray) object;
            } else {
                if (object instanceof JSONObject) {
                    JSONObject j = (JSONObject) object;
                    if (j.isEmpty()) {
                        array = new JSONArray(); // just take it as an empty list
                    }
                } else {
                    if (object instanceof String) {
                        array = new JSONArray();
                        array.add(object);
                    } else {
                        throw new OA2JSONException(
                                OA2Errors.INVALID_REQUEST,
                                "cannot interpret " + key + ", got " + object,
                                HttpStatus.SC_BAD_REQUEST,
                                null, client);
                    }
                }
            }
        }
        return array;
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
            if (!responseTypes.isEmpty()) {
                // oidc-agent sends an empty list. Don't have it bomb later.
                if (!responseTypes.contains(OA2Constants.RESPONSE_TYPE_CODE)) {
                    throw new OA2JSONException(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                            "unsupported response type",
                            HttpStatus.SC_BAD_REQUEST, null, client);
                }
                if (responseTypes.contains(OA2Constants.RESPONSE_TYPE_TOKEN)) {
                    // This is required for implicit flow, which we do not support.
                    throw new OA2JSONException(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                            "unsupported response type",
                            HttpStatus.SC_BAD_REQUEST, null, client);

                }
                if (1 < responseTypes.size() && !checkJAEntry(responseTypes, OA2Constants.RESPONSE_TYPE_ID_TOKEN)) {
                    throw new OA2JSONException(OA2Errors.UNSUPPORTED_RESPONSE_TYPE,
                            "unsupported response type",
                            HttpStatus.SC_BAD_REQUEST, null, client);

                }
                client.setResponseTypes(responseTypes);
            }
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
                    OA2Constants.GRANT_TYPE_REFRESH_TOKEN,
                    GRANT_TYPE_DEVICE_FLOW, // CIL-1101 fix
                    GRANT_TYPE_TOKEN_EXCHANGE};
            if (!areAllGrantsSupported(grantTypes, supportedGrants)) {
                throw new OA2JSONException(OA2Errors.REGISTRATION_NOT_SUPPORTED,
                        "unsupported grant type",
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
                    Object raw = jsonRequest.get(keys.rtLifetime());
                    if (raw instanceof Integer) {
                        client.setRtLifetime(((Integer) raw) * 1000L);
                    } else {
                        if (raw instanceof Long) {
                            // assumption is they are sending it in seconds
                            client.setRtLifetime(((Long) raw) * 1000L);
                        } else {
                            client.setRtLifetime(XMLConfigUtil.getValueSecsOrMillis(raw.toString(), true));
                        }
                    }
                } else {
                    // Fix for https://github.com/ncsa/oa4mp/issues/176
                    // Case is that the grant is given requesting refresh tokens, but no actual
                    // value is set.
                    client.setRtLifetime(OA2Client.USE_SERVER_DEFAULT);// server default
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
        JSONArray array = null;
        Object object = obj.get(key);
        if (object instanceof JSONArray) {
            array = (JSONArray) object;

        } else {
            if (object instanceof JSONObject) {
                if (((JSONObject) object).isEmpty()) {
                    array = new JSONArray();
                }
            }
            if (object instanceof String) {
                String rawScopes = obj.getString(key);
                StringTokenizer st = new StringTokenizer(rawScopes, " ");
                array = new JSONArray();
                while (st.hasMoreTokens()) {
                    String nextScope = st.nextToken();
                    if (!array.contains(nextScope)) {
                        array.add(nextScope);
                    }
                }
            }
            // so they did not send along a JSON array. Other option is a string

        }
        return array;
    }

    protected OA2Client processRegistrationRequest(JSONObject jsonRequest,
                                                   AdminClient adminClient,
                                                   boolean isAnonymous,
                                                   OA2Client client,
                                                   String version) {

        return updateClient(client, adminClient, isAnonymous, jsonRequest, true, version);
    }

    SecureRandom random = new SecureRandom();
    String anonSubjectTemplate = "CILogon anonymous client ${action}";
    String anonMessageTemplate = "An anonymous client was ${action}:\n\n${client} ";
    String subjectTemplate = "CILogon client ${action} for ${admin_name}";
    String messageTemplate = "The \"${admin_name}\" (${admin_id}) ${action} the following client:\n\n${client} ";

    //CIL-607
    protected void fireMessage(boolean isAnonymous, OA2SE oa2SE, HashMap<String, String> replacements) {
        if (isAnonymous) {
            oa2SE.getMailUtil().sendMessage(anonSubjectTemplate, anonMessageTemplate, replacements, oa2SE.getNotifyACEventEmailAddresses());
        } else {
            oa2SE.getMailUtil().sendMessage(subjectTemplate, messageTemplate, replacements, oa2SE.getNotifyACEventEmailAddresses());
        }
    }

    public JWKUtil2 getJwkUtil() {
        if (jwkUtil == null) {
            jwkUtil = new JWKUtil2();
        }
        return jwkUtil;
    }

    public void setJwkUtil(JWKUtil2 jwkUtil) {
        this.jwkUtil = jwkUtil;
    }

    JWKUtil2 jwkUtil;

}
