package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractRegistrationServlet;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.JWTRunner;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC9068Constants;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.qdl.scripting.AnotherJSONUtil;
import edu.uiuc.ncsa.qdl.scripting.QDLScript;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine.CONFIG_TAG;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.ALL_PHASES;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.SRE_EXEC_PHASE;

/**
 * A budding set of utilities for working with clients.
 * <p>Created by Jeff Gaynor<br>
 * on 3/17/14 at  12:57 PM
 */
public class OA2ClientUtils {
    /**
     * Note that all of the exceptions thrown here are because the callback cannot be verified, hence it is unclear
     * where the error is to be sent.
     *
     * @param client
     * @param redirect
     */
    public static void check(Client client, String redirect) {

        if (client == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "no client id",
                    HttpStatus.SC_BAD_REQUEST, null);
        }
        if (!(client instanceof OA2Client)) {
            throw new NFWException("Internal error: Client is not an OA2Client");
        }

        OA2Client oa2Client = (OA2Client) client;


        boolean foundCB = false;
        if (oa2Client.getCallbackURIs() == null) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "client has not registered any callback URIs",
                    HttpStatus.SC_BAD_REQUEST,
                    null, oa2Client);
        }
        for (String uri : oa2Client.getCallbackURIs()) {
            if (uri.equals(redirect)) {
                foundCB = true;
                break;
            }
        }

        if (!foundCB) {
            ServletDebugUtil.trace(OA2ClientUtils.class,
                    "invalid redirect uri for client \"" +
                            oa2Client.getIdentifierString() + "\": \"" + redirect + "\"");
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "The given " + OA2Constants.REDIRECT_URI + " is not valid for this client.",
                    HttpStatus.SC_BAD_REQUEST,
                    null, oa2Client);
        }
    }


    /**
     * This takes a list of callbacks and checks policies for each of them. This does the actual work for checking
     *
     * @param rawCBs
     * @param dudUris -- this is a list of any URIs that are rejected. The caller may do with them what they will.
     * @return
     * @throws IOException
     */
    public static LinkedList<String> createCallbacks(List<String> rawCBs,
                                                     List<String> dudUris) throws IOException {
        LinkedList<String> uris = new LinkedList<>();

        for (String x : rawCBs) {
            // Fix for CIL-609 -- don't add empty strings or white space.
            if (x == null || x.isEmpty() || x.trim().isEmpty()) {
                continue;
            }
            // Fix for CIL-545. Allowing a wider range of redirect URIs to support devices such as smart phones.
            // How it works: Either the protocol is not http/https in which case it is allowed
            // but if it is http, only localhost is permitted. Any https works.
            try {
                // CIL-871 fix -- no wildcards allowed.
                if (x.contains("*")) {
                    throw new IllegalArgumentException("Error: wildcard in \"" + x + "\" is not allowed.");
                }

                URI temp = URI.create(x);
                // Fix for CIL-739, accept only absolute URIs
                if (!temp.isAbsolute()) {
                    throw new IllegalArgumentException("Error: uri \"" + temp + "\" is not absolute.");
                }
                String host = temp.getHost();
                String scheme = temp.getScheme();
                ServletDebugUtil.trace(OA2ClientUtils.class, "createCallbacks, processing callback \"" + x + "\"");

                if (scheme != null && scheme.toLowerCase().equals("https")) {
                    // any https works
                    uris.add(x);
                } else {
                    if (isPrivate(host, scheme)) {
                        uris.add(x);
                    } else {
                        if (temp.getAuthority() == null || temp.getAuthority().isEmpty()) {
                                  /*
                                  Finally, if it does not have an authority, then it is probably
                                  an intention for another (probably mobile) device (so in that case,
                                  the browser on the device has the table associating schemes with
                                  specific applications. When it sees a uri with this scheme, it
                                  invokes the associated application and hands it the URI. This allows
                                  the browser to do a redirect to an application. The requirement is that there is a scheme, but
                                  there is no authority:
                                   E.g. https://bob@foo.com/blah/woof
                                   has authority of "//bob@foo.com/"

                                   An example of what this block allows (or should) is a uri like

                                   com.example.app:/oauth2redirect/example-provider

                                   which has a scheme, no authority and a path.
                                   */
                            uris.add(x);
                        } else {
                            dudUris.add(x);
                        }
                    }
                }

            } catch (IllegalArgumentException urisx) {
                dudUris.add(x);
            }

              /*  Old stuff before CIL-545
                 if (!x.toLowerCase().startsWith("https:")) {
                      warn("Attempt to add bad callback uri for client " + client.getIdentifierString());
                      throw new ClientRegistrationRetryException("The callback \"" + x + "\" is not secure.", null, client);
                  }
                  URI.create(x); // passes here means it is a uri. All we want this to do is throw an exception if needed.

                  uris.add(x);*/
        }
        return uris;
    }

    /**
     * This is for use with the web interface. The string in this case is the contents of a textbox that has
     * one callback per line. Each callback is processed.
     *
     * @param client
     * @param rawCBs
     * @return
     * @throws IOException
     */
    public static LinkedList<String> createCallbacksForWebUI(OA2Client client,
                                                             String rawCBs) throws IOException {
        BufferedReader br = new BufferedReader(new StringReader(rawCBs));
        String x = br.readLine();

        LinkedList<String> uris = new LinkedList<>();
        LinkedList<String> dudUris = new LinkedList<>();

        while (x != null) {
            uris.add(x);
            x = br.readLine();
        }
        br.close();
        LinkedList<String> foundURIs = createCallbacks(uris, dudUris);
        if (0 < dudUris.size()) {
            String xx = "</br>";
            boolean isOne = dudUris.size() == 1;
            for (String y : dudUris) {
                xx = xx + y + "</br>";
            }
            String helpfulMessage = "The callback" + (isOne ? " " : "s ") + xx + (isOne ? "is" : "are") + " not valid.";
            throw new AbstractRegistrationServlet.ClientRegistrationRetryException(helpfulMessage, null, client);

        }

        return foundURIs;

    }

    /**
     * Used when resolving which network from its dotted quad address.
     *
     * @param address
     * @return
     */
    protected static int[] toQuad(String address) {
        StringTokenizer stringTokenizer = new StringTokenizer(address, ".");
        if (!stringTokenizer.hasMoreTokens()) {
            return null;
        }
        int[] quad = new int[4];

        for (int i = 0; i < 4; i++) {
            if (!stringTokenizer.hasMoreTokens()) {
                return null;
            }
            String raw = stringTokenizer.nextToken();
            try {
                quad[i] = Integer.parseInt(raw);
                if (!(0 <= quad[i] && quad[i] <= 255)) {
                    return null;
                }
            } catch (NumberFormatException nfx) {
                return null;
            }
        }
        if (stringTokenizer.hasMoreTokens()) {
            return null;
        }
        return quad;

    }

    protected static boolean isOnPrivateNetwork(String address) {
        String regex = "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
        if (!address.matches(regex)) {
            return false;
        }
        int[] quad = toQuad(address);
        if (quad == null) {
            return false;
        }
        if (quad[0] == 10) {
            return true;
        }

        // This just checked that it is a dotted quad address. We could have used InetAddress which
        // only checks a valid dotted quad for format, **but** might also do an actual address lookup
        // if there is a question, so that really doesn't help.

        // We have to check that address in the range 192.168.x.x  are included. (standard home network)
        // We have to check that address in the range 172.16.x.x to 172.31.x.x are included.
        if (quad[0] == 192 && quad[1] == 168) return true;
        if (quad[0] == 172 && (16 <= quad[1] && quad[1] <= 31)) return true;
        if (quad[0] == 127 && quad[1] == 0 && quad[2] == 0 && quad[3] == 1) return true;

        return false;
    }

    protected static boolean isPrivate(String host, String scheme) {
        if (host != null && isOnPrivateNetwork(host)) {
            // scheme does not matter in this case since it is a private network.
            // note that this also catches the loopback address of 127.0.0.1
            return true;
        }
        if (scheme != null && scheme.toLowerCase().equals("http")) {
            // only localhost works for http
            if (host.toLowerCase().equals("localhost") ||
                    host.equals("[::1]")) {
                return true;
            }
        }


        return false;
    }


    public static void setupHandlers(JWTRunner jwtRunner,
                                     OA2SE oa2SE,
                                     OA2ServiceTransaction transaction,
                                     OA2Client client,
                                     HttpServletRequest req) throws Throwable {
        setupHandlers(jwtRunner, oa2SE, transaction, client, null, null, null, req);
    }


    public static void setupHandlers(JWTRunner jwtRunner,
                                     OA2SE oa2SE,
                                     OA2ServiceTransaction transaction,
                                     OA2Client client,
                                     TXRecord idTX,
                                     TXRecord atTX,
                                     TXRecord rtTX,
                                     HttpServletRequest req) throws Throwable {
        MetaDebugUtil debugger = DebugUtil.getInstance();
        if (transaction.getClient().isDebugOn()) {
            debugger = new MetaDebugUtil();
            debugger.setIsEnabled(true);
        }
        debugger.trace(OA2ClientUtils.class, "Setting up handlers");
        //OA2Client client = (OA2Client) transaction.getClient();
        // Allow a client to skip any server scripts on a case by case basis.
        if (!client.isSkipServerScripts() && oa2SE.getQDLEnvironment().hasServerScripts()) {
            ServerQDLScriptHandlerConfig qdlScriptHandlerConfig = new ServerQDLScriptHandlerConfig(oa2SE, transaction, atTX, req);
            ServerQDLScriptHandler qdlScriptHandler = new ServerQDLScriptHandler(qdlScriptHandlerConfig);
            jwtRunner.addHandler(qdlScriptHandler);
        }
        PayloadHandlerConfigImpl idthCfg = null;
        if (client.hasIDTokenConfig()) {
            debugger.trace(OA2ClientUtils.class, "has id token config, creating handler");
            idthCfg = new PayloadHandlerConfigImpl(
                    client.getIDTokenConfig(),
                    oa2SE,
                    transaction,
                    idTX,
                    req);
            switch (client.getIDTokenConfig().getType()) {
                case IDTokenHandler.ID_TOKEN_DEFAULT_HANDLER_TYPE:
                case IDTokenHandler.ID_TOKEN_BASIC_HANDLER_TYPE:
                    // we're good
                    break;
                default:
                    throw new IllegalArgumentException("unknown identity token handler type");
            }

        } else {
            // Legacy case. Functors have no config, but need a handler to get the init and accounting information.
            debugger.trace(OA2ClientUtils.class, "Found legacy id token configuration.");

            idthCfg = new PayloadHandlerConfigImpl(
                    new IDTokenClientConfig(),  // here is the trick: An empty object triggers a hunt for functors.
                    oa2SE,
                    transaction,
                    atTX,
                    req);
            idthCfg.setLegacyHandler(true);
        }
        IDTokenHandler idTokenHandler = new IDTokenHandler(idthCfg);
        jwtRunner.setIdTokenHandlerInterface(idTokenHandler);

        if (client.hasAccessTokenConfig()) {
            debugger.trace(OA2ClientUtils.class, "has access token config, creating handler, type="
                    + client.getAccessTokensConfig().getType());
            PayloadHandlerConfigImpl st = new PayloadHandlerConfigImpl(
                    client.getAccessTokensConfig(),
                    oa2SE,
                    transaction,
                    atTX,
                    req);
            AbstractAccessTokenHandler sth = null;
            switch (client.getAccessTokensConfig().getType()) {
                case WLCGTokenHandler.WLCG_TAG:
                    sth = new WLCGTokenHandler(st);
                    debugger.trace(OA2ClientUtils.class, "WLCG access token handler created");
                    break;
                case SciTokenConstants.SCI_TOKEN_TAG2:
                case SciTokenConstants.SCI_TOKEN_TAG:
                    sth = new ScitokenHandler(st);
                    debugger.trace(OA2ClientUtils.class, "SciTokens access token handler created");
                    break;
                case RFC9068Constants.RFC9068_TAG:
                case RFC9068Constants.RFC9068_TAG2:
                    sth = new RFC9068ATHandler(st);
                    debugger.trace(OA2ClientUtils.class, "RFC 9068 access token handler created");
                    break;
                case AbstractAccessTokenHandler.AT_DEFAULT_HANDLER_TYPE:
                case AbstractAccessTokenHandler.AT_BASIC_HANDLER_TYPE:
                    sth = new AbstractAccessTokenHandler(st);
                    debugger.trace(OA2ClientUtils.class, "generic access token handler created");
                    break;
                default:
                    debugger.trace(OA2ClientUtils.class, "unknown handler of type \"" + client.getAccessTokensConfig().getType() + "\" requested.");
                    throw new IllegalArgumentException("unknown access token handler type");
            }
            jwtRunner.setAccessTokenHandler(sth);
        }
        if (client.hasRefreshTokenConfig()) {
            debugger.trace(OA2ClientUtils.class, "has refresh token config, creating handler");

            PayloadHandlerConfigImpl st = new PayloadHandlerConfigImpl(
                    client.getRefreshTokensConfig(),
                    oa2SE,
                    transaction,
                    rtTX,
                    req);
            BasicRefreshTokenHandler rth = new BasicRefreshTokenHandler(st);
            switch (client.getRefreshTokensConfig().getType()) {
                case BasicRefreshTokenHandler.REFRESH_TOKEN_DEFAULT_HANDLER_TYPE:
                case BasicRefreshTokenHandler.REFRESH_TOKEN_BASIC_HANDLER_TYPE:
                    break;
                default:
                    throw new IllegalArgumentException("unknown refresh token handler type");

            }
            jwtRunner.setRefreshTokenHandler(rth);
        }
    }

    public static List<String> scopesFromTemplates(List<String> scopes, OA2ServiceTransaction t) {
        List<String> computedScopes = new ArrayList<>();
        return computedScopes;

    }

    public static OA2Client resolvePrototypes(OA2SE oa2SE, OA2Client baseClient) {
        return resolvePrototypes(oa2SE.getClientStore(), baseClient);
    }

    public static OA2Client resolvePrototypes(ClientStore store, OA2Client baseClient) {
        if (!baseClient.hasPrototypes()) {
            return baseClient; // end of story
        }
        ColumnMap clientMap = new ColumnMap();
        MapConverter mapConverter = store.getMapConverter();
        mapConverter.toMap(baseClient, clientMap);
        OA2ClientKeys oa2ClientKeys = (OA2ClientKeys) mapConverter.getKeys();
        // If a key is in the following, skip it. Clients keep their secret, id and name
        // generally
        HashSet<String> skipSet = new HashSet<>();
        skipSet.add(oa2ClientKeys.secret());
        skipSet.add(oa2ClientKeys.identifier());
        skipSet.add(oa2ClientKeys.name());

        for (Identifier id : baseClient.getPrototypes()) {
            OA2Client currentClient = (OA2Client) store.get(id);
            if (currentClient == null) {
                throw new UnknownClientException("client \"" + id + "\" does not exist");
            }
            ColumnMap map = new ColumnMap();
            mapConverter.toMap(currentClient, map);
            for (String key : map.keySet()) {
                // skip secrets and identifiers!!!
                if (skipSet.contains(key)) {
                    continue;
                }
                Object obj = map.get(key);
                if (obj instanceof Long) {
                    long pValue = (Long) obj;
                    long eValue = -1L; // means override
                    if(clientMap.containsKey(key)){
                        eValue = clientMap.getLong(key);
                    }
                    if(eValue <0){
                        // use the original value
                        clientMap.put(key, pValue);
                    }else{
                    }
                } else {
                    if (obj instanceof Integer) {
                        int pValue = (Integer) obj;
                        int eValue = -1;
                        if(clientMap.containsKey(key)){
                            eValue = clientMap.getInteger(key);
                        }
                        if(eValue < 0){
                            // use original
                            clientMap.put(key, pValue);
                        }else{
                        }
                    } else {
                        clientMap.put(key, obj);
                    }
                }
            }
        }

        OA2Client client = (OA2Client) store.getMapConverter().fromMap(clientMap, null);
        client.setReadOnly(true);
        return client;
    }

    /**
     * Assumes that the configuration for the client is just a qdl script element or list of them.
     *
     * @param pc
     * @param client
     */
    public static void setupDriverPayloadConfig(AbstractPayloadConfig pc, OA2Client client) {
        JSONObject cfg = client.getConfig();
        ScriptSet<? extends QDLScript> scriptSet;
        // Options are it is a single QDL load command or an array of them.
        if (cfg.get(CONFIG_TAG) instanceof JSONArray) {
            scriptSet = AnotherJSONUtil.createScripts(cfg.getJSONArray(CONFIG_TAG));
        } else {
            scriptSet = AnotherJSONUtil.createScripts(cfg.getJSONObject(CONFIG_TAG));
        }
        Iterator<? extends QDLScript> iterator = scriptSet.iterator();
        while (iterator.hasNext()) {
            QDLScript script = iterator.next();
            if (!script.getProperties().containsKey(SRE_EXEC_PHASE)) {
                script.getProperties().put(SRE_EXEC_PHASE, ALL_PHASES);
            }
        }
        pc.setScriptSet(scriptSet);
    }
}
