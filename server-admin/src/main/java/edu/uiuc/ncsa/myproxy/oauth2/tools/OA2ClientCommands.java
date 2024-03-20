package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oauth2.base.ClientApprovalStoreCommands;
import edu.uiuc.ncsa.myproxy.oauth2.base.ClientStoreCommands;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client.USE_SERVER_DEFAULT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:24 PM
 */
public class OA2ClientCommands extends ClientStoreCommands {
    public OA2ClientCommands(MyLoggingFacade logger,
                             String defaultIndent,
                             Store clientStore,
                             ClientApprovalStoreCommands clientApprovalStoreCommands,
                             PermissionsStore permissionsStore) throws Throwable {
        super(logger, defaultIndent, clientStore, clientApprovalStoreCommands);
        setPermissionsStore(permissionsStore);
    }

    public PermissionsStore getPermissionsStore() {
        return permissionsStore;
    }

    public void setPermissionsStore(PermissionsStore permissionsStore) {
        this.permissionsStore = permissionsStore;
    }

    PermissionsStore permissionsStore;

    public UUCConfiguration getUucConfiguration() {
        return uucConfiguration;
    }

    public void setUucConfiguration(UUCConfiguration uucConfiguration) {
        this.uucConfiguration = uucConfiguration;
    }

    UUCConfiguration uucConfiguration;

    public boolean isRefreshTokensEnabled() {
        return refreshTokensEnabled;
    }

    public void setRefreshTokensEnabled(boolean refreshTokensEnabled) {
        this.refreshTokensEnabled = refreshTokensEnabled;
    }

    boolean refreshTokensEnabled;

    public Collection<String> getSupportedScopes() {
        return supportedScopes;
    }

    public void setSupportedScopes(Collection<String> supportedScopes) {
        this.supportedScopes = supportedScopes;
    }

    Collection<String> supportedScopes = null;

    @Override
    public void print_help() throws Exception {
        super.print_help();
        say("-- Client specific commands:");
        sayi("cb = manage the callbacks directly");
    }

    protected void showCBHelp() {
        say("cb -add [cb1, cb2,...] index =  add a list of callbacks to the given list of callbacks. If no list is given, you will be prompted");
        say("cb -list /index = list the callbacks for a given client");
        say("cb -rm [cb1, cb2,...] /index = remove the given callbacks from the client.");
        say("Note that you must supply a list of callbacks");
        say("\nE.g. to add a a few callbacks you would invoke");
        say("cb -add https://foo1, https://foo2,https://foo3 /oa4mp:client/id/234234234234");
        say("\nThis adds the three urls to the current list for the client with the given id.");
    }


    public void cb(InputLine inputLine) throws IOException {
        if (showHelp(inputLine)) {
            showCBHelp();
            return;
        }
        boolean gotOne = false;
        OA2Client client = (OA2Client) findItem(inputLine);
        if (inputLine.hasArg("-add")) {
            gotOne = true;
            Collection<String> cbs = getCBS(inputLine);
            // form is that the last argument is the index, so there has to be at least
            processDBAdd(client, cbs);
            return;
        }
        if (inputLine.hasArg("-rm")) {
            gotOne = true;
            Collection<String> cbs = getCBS(inputLine);
            removeCB(client, cbs);
            return;
        }
        if (inputLine.hasArg("-list")) {
            gotOne = true;
            say("list of callbacks for this client:");
            for (String x : client.getCallbackURIs()) {
                say("  " + x);
            }
            return;
        }
        if (!gotOne) {
            say("Sorry, no command found. Show help for this topic if you need to.");
        }
    }

    protected void removeCB(OA2Client client, Collection<String> cbs) throws IOException {
        if (cbs.isEmpty()) {
            //    say("Enter callbacks to remove. A blank line ends input");
            say("nothing to remove");

        }
        client.getCallbackURIs().remove(cbs);
        String response = getInput("Save?(y/n)", "n");
        if (response.equals("y")) {
            getStore().save(client);
            say("done.");
        } else {
            say("not saved.");
        }
    }

    protected Collection<String> getCBS(InputLine inputLine) {
        Collection<String> cbs = new LinkedList<>();
        List<String> allArgs = inputLine.getArgs();
        // have to pull off the arguments. The input line looks like e.g.
        // -add A,B, C,  D,E  /index
        // where we need to normalize it to A,B,C,D,E and then split it, inspect each one as a URL
        String newCBs = "";
        for (int i = 1; i < allArgs.size() - 1; i++) {
            newCBs = newCBs + allArgs.get(i).trim();
        }
        if (!newCBs.isEmpty()) {
            StringTokenizer st = new StringTokenizer(newCBs, ",");
            while (st.hasMoreTokens()) {
                String nextToken = st.nextToken();
                try {
                    // This exists to verify that the entered value is a URI, naught else.
                    URI tempURI = URI.create(nextToken);
                  /*  if (!tempURI.getScheme().equals("https")) {
                        say("Sorry but the protocol for \"" + nextToken + "\" is not supported. It must be https. Rejected.");
                    } else {*/
                    cbs.add(nextToken);
                    //}
                } catch (Throwable t) {
                    say("Sorry but \"" + nextToken + "\" is not a valid URL. Skipped.");
                }
            }
        }
        return cbs;
    }

    protected void processDBAdd(OA2Client client, Collection<String> newArgs) throws IOException {
        if (newArgs.isEmpty()) {
            //   say("No callbacks, please enter them as a comma separated list. Empty line ends input.");
            //  String line = readline();
            say("No callbacks to add.");
            return;
        } else {
            client.getCallbackURIs().addAll(newArgs);

        }
        String response = getInput("Save changes?(y/n)", "n");
        if (response.equals("y")) {
            getStore().save(client);
            say("Saved.");
        } else {
            say("not saved.");
        }
    }

    /**
     * In this case, the secret has to be gotten and processed into a hash,
     * callback uris listed and the refresh token lifetime set.
     * <p>Caveat: This is also called for mass updates, not just create so always
     * check for existing values.</p>
     *
     * @param identifiable
     */
    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {
        OA2ClientKeys keys = (OA2ClientKeys) getSerializationKeys();
        OA2Client oa2Client = (OA2Client) identifiable;
        super.extraUpdates(oa2Client, magicNumber);
        final String DEFAULT_SERVER_VALUE = "default";
        String rawAT = oa2Client.getAtLifetime() == USE_SERVER_DEFAULT ? DEFAULT_SERVER_VALUE : Long.toString(oa2Client.getAtLifetime());

        rawAT = getPropertyHelp(keys.atLifetime(), "enter access token lifetime in seconds or " + DEFAULT_SERVER_VALUE, rawAT);
        if (rawAT.equals(DEFAULT_SERVER_VALUE)) {
            oa2Client.setAtLifetime(USE_SERVER_DEFAULT);
        } else {
            try {
                oa2Client.setAtLifetime(Long.parseLong(rawAT) * 1000);
            } catch (Throwable t) {
                say("  could not parse " + rawAT + ", using server default");
                oa2Client.setAtLifetime(USE_SERVER_DEFAULT);
            }
        }
        rawAT = oa2Client.getMaxATLifetime() == USE_SERVER_DEFAULT ? DEFAULT_SERVER_VALUE : Long.toString(oa2Client.getMaxATLifetime());
        rawAT = getPropertyHelp(keys.maxATLifetime(), "  enter max access token lifetime in seconds or " + DEFAULT_SERVER_VALUE, rawAT);
        if (rawAT.equals(DEFAULT_SERVER_VALUE)) {
            oa2Client.setMaxRTLifetime(USE_SERVER_DEFAULT);
        } else {
            try {
                oa2Client.setMaxATLifetime(Long.parseLong(rawAT) * 1000);
            } catch (Throwable tt) {
                say("  could not parse " + rawAT + ", using server default");
                oa2Client.setMaxATLifetime(USE_SERVER_DEFAULT); // negative value means use whatever the server max is.
            }

        }
        if (isRefreshTokensEnabled()) {
            // so at this point the server actually allows for refresh tokens
            // The next bit gives the user the option of "none" meaning they can disable refresh tokens too
            // without having to know internal state values.
            final String RT_DISABLED = "none";
            String rtString;
            // can't use switch on long values.
            if (oa2Client.getRtLifetime() == USE_SERVER_DEFAULT) {
                rtString = DEFAULT_SERVER_VALUE;
            } else {
                if (oa2Client.getRtLifetime() == OA2Client.DISABLE_REFRESH_TOKENS) {
                    rtString = RT_DISABLED;
                } else {
                    rtString = Long.toString(oa2Client.getMaxRTLifetime());
                }
            }
            String rawLifetime = getPropertyHelp(keys.rtLifetime(), "enter the refresh lifetime in sec., " + RT_DISABLED + ", or " + DEFAULT_SERVER_VALUE, rtString);
            switch (rawLifetime) {
                case RT_DISABLED:
                    oa2Client.setRtLifetime(OA2Client.DISABLE_REFRESH_TOKENS);
                    break;
                case DEFAULT_SERVER_VALUE:
                    oa2Client.setRtLifetime(USE_SERVER_DEFAULT);
                    break;
                default:
                    try {
                        oa2Client.setRtLifetime(Long.parseLong(rawLifetime) * 1000L);
                    } catch (Throwable t) {
                        sayi("Could not parse \"" + rawLifetime + "\", no change.");
                    }
            }
            if (oa2Client.getMaxRTLifetime() == USE_SERVER_DEFAULT) {
                rawLifetime = DEFAULT_SERVER_VALUE;
            } else {
                rawLifetime = Long.toString(oa2Client.getMaxRTLifetime());
            }
            rawLifetime = getPropertyHelp(keys.maxRTLifetime(),
                    "  enter max refresh token lifetime in seconds or " + DEFAULT_SERVER_VALUE,
                    rawLifetime);
            if (rawLifetime.equals(DEFAULT_SERVER_VALUE)) {
                oa2Client.setMaxRTLifetime(USE_SERVER_DEFAULT);
            } else {
                try {
                    oa2Client.setMaxRTLifetime(Long.parseLong(rawLifetime));
                } catch (Throwable t) {
                    say(" could not parse \"" + rawLifetime + "\", no change");
                }
            }
            // now do grace periods. These are complex.
            // Again, no switch for longs.
            long rtGracePeriod = oa2Client.getRtGracePeriod();
            if (rtGracePeriod == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DISABLED) {
                rawLifetime = RT_DISABLED;
            } else {
                if (rtGracePeriod == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT) {
                    rawLifetime = DEFAULT_SERVER_VALUE;
                } else {
                    if (rtGracePeriod == OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_NOT_CONFIGURED) {
                        // not configured means no action has been taken, so set to default
                        rawLifetime = Long.toString(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DEFAULT);
                    } else {
                        rawLifetime = Long.toString(rtGracePeriod);
                    }
                }
            }
            rawLifetime = getPropertyHelp(keys.rtGracePeriod(), "  enter grace period in sec., " + RT_DISABLED + ", or " + DEFAULT_SERVER_VALUE, rawLifetime);
            switch (rawLifetime) {
                case RT_DISABLED:
                    oa2Client.setRtGracePeriod(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DISABLED);
                    break;
                case DEFAULT_SERVER_VALUE:
                    oa2Client.setRtGracePeriod(OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT);
                    break;
                default:
                    try {
                        oa2Client.setRtGracePeriod(Long.parseLong(rawLifetime));
                    } catch (Throwable t) {
                        say("could not parse \"" + rawLifetime + "\", no change");
                    }
                    break;
            }
        }
        oa2Client.setPublicClient(getPropertyHelp(keys.publicClient(),
                "is this client public (y/n)?",
                Boolean.toString(oa2Client.isPublicClient())).equalsIgnoreCase("y"));

        String currentScopes = null;
        if (oa2Client.getScopes() != null) {
            boolean firstPass = true;
            for (String x : oa2Client.getScopes()) {
                if (firstPass) {
                    firstPass = false;
                    currentScopes = x;
                } else {
                    currentScopes = currentScopes + "," + x;
                }
            }
        }
        //String scopes = getPropertyHelp(keys.scopes(),"enter a comma separated list of scopes. Scopes to this server will be rejected.", currentScopes);
        // https://github.com/rcauth-eu/OA4MP/commit/67141fd26ac001d8bc38be21219cbb72e2bdd011
        String scopes = getPropertyHelp(keys.scopes(), "enter a comma separated list of scopes. Other scopes to this server will be rejected.", currentScopes);
        if (!(scopes == null || scopes.isEmpty())) {
            LinkedList<String> list = new LinkedList<>();
            StringTokenizer stringTokenizer = new StringTokenizer(scopes, ",");
            while (stringTokenizer.hasMoreTokens()) {
                String raw = stringTokenizer.nextToken().trim();
                if (getSupportedScopes().contains(raw)) {
                    list.add(raw);
                } else {
                    say("Unknown scope \"" + raw + "\" rejected.");
                }
            }
            oa2Client.setScopes(list);
        }
        oa2Client.setStrictscopes(getPropertyHelp(keys.strictScopes(), "strict scopes (y/n)", "y").equalsIgnoreCase("y"));

        // Now do much the same for the list of callback URIs
        String currentUris = null;
        if (oa2Client.getCallbackURIs() != null) {
            boolean firstPass = true;
            for (String x : oa2Client.getCallbackURIs()) {
                if (firstPass) {
                    firstPass = false;
                    currentUris = x;
                } else {
                    currentUris = currentUris + "," + x;
                }
            }
        }
        String uris = getPropertyHelp(keys.callbackUri(), "enter a comma separated list of callback uris. These must start with https or they will be ignored.", currentUris);

        if (!StringUtils.isTrivial(uris)) {
            StringTokenizer stringTokenizer = new StringTokenizer(uris, ",");
            LinkedList<String> rawCBs = new LinkedList<>();
            while (stringTokenizer.hasMoreTokens()) {
                rawCBs.add(stringTokenizer.nextToken().trim());
            }
            LinkedList<String> dudURIs = new LinkedList<>();
            List<String> foundURIs = null;
            try {
                foundURIs = OA2ClientUtils.createCallbacks(rawCBs, dudURIs);
            } catch (IOException iox) {
                say("Sorry, there was an error processing the uris:\"" + iox.getMessage() + "\"");
                return;
            }
            if (0 < dudURIs.size()) {
                say(dudURIs.size() + " uris rejected:");
                for (String dud : dudURIs) {
                    say("  " + dud);
                }
            }
            if (foundURIs == null) {
                // This ***should** be impossible.
                say("There was an error processing the URIs");
                return;
            }
            oa2Client.setCallbackURIs(foundURIs);
        }
        if (getInput("do advanced options (y/n)?", "n").equalsIgnoreCase("y")) {
            boolean isServiceClient = getPropertyHelp(keys.rfc7523Client(), "service client (y/n)?", "n").equalsIgnoreCase("y");
            if (isServiceClient) {
                oa2Client.setServiceClient(true);
                oa2Client.setServiceClientUsers(processCommaSeparatedList(keys.rfc7523ClientUsers(), "allowed users", "*"));
            }
            // can't do getPropertyHelp in the next line since no single key for proxies.
            boolean configProxies = isOk(getInput("configure proxies (y/n)?", "n"));
            if (configProxies) {
                oa2Client.setForwardScopesToProxy(isOk(keys.forwardScopesToProxy() + " (y/n)?"));
                if (!oa2Client.isForwardScopesToProxy()) {
                    oa2Client.setProxyRequestScopes(processCommaSeparatedList(keys.proxyRequestScopes(), "scopes", "*"));
                }
                oa2Client.setProxyClaimsList(processCommaSeparatedList(keys.proxyClaimsList(), "claims", "*"));
            }

            String issuer = getPropertyHelp(keys.issuer(), "enter the issuer (optional)", oa2Client.getIssuer());
            if (!isEmpty(issuer)) {
                oa2Client.setIssuer(issuer);
            }
            if (getPropertyHelp(keys.ersatzClient(), "is ersatz client (y/n)?", "n").equalsIgnoreCase("y")) {
                oa2Client.setErsatzClient(true);
                oa2Client.setExtendsProvisioners(getPropertyHelp(keys.extendsProvisioners(), "  extends the provisioner (y/n)?", "y").equalsIgnoreCase("y"));
                oa2Client.setErsatzInheritIDToken(getPropertyHelp(keys.ersatzInheritIDToken(), "  inherit the ID token from the provisioner on fork(y/n)?", "y").equalsIgnoreCase("y"));
                // naming the provisioners requirings setting permissions and is not done here.
                say("  To link this client to its provisioners, use the ersatz command");
            } else {
                oa2Client.setErsatzClient(false);
            }
            List<String> prototypes = processCommaSeparatedList(keys.prototypes(), "prototypes", "");
            if (!prototypes.isEmpty()) {
                List<Identifier> identifiers = new ArrayList<>();
                List<String> bad = new ArrayList<>();
                for (String p : prototypes) {
                    try {
                        identifiers.add(BasicIdentifier.newID(p));
                    } catch (Throwable t) {
                        bad.add(p);
                    }
                }
                oa2Client.setPrototypes(identifiers);
                if (!bad.isEmpty()) {
                    say("  rejected the following bad identifier(s):" + bad);
                }
            }
            String signTokens = getPropertyHelp(keys.signTokens(), "Enable ID token signing (true/false)?", Boolean.toString(oa2Client.isSignTokens()));
            if (!isEmpty(signTokens)) {
                try {
                    oa2Client.setSignTokens(Boolean.parseBoolean(signTokens));
                } catch (Throwable t) {
                    // do nothing.
                    sayi("Unknown response of \"" + signTokens + "\". Must be \"true\" or \"false\", ignoring.");
                }
            }
            JSON currentLDAPs = null;
            LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

            if (oa2Client.getLdaps() == null || oa2Client.getLdaps().isEmpty()) {
                //            currentLDAPs = null;
            } else {
                // moving this here. If there are older LDAP configurations you can edit them, but can't add new ones.
                // These are officially not supported any longer.
                currentLDAPs = ldapConfigurationUtil.toJSON(oa2Client.getLdaps());
                JSONArray newLDAPS = (JSONArray) inputJSON(currentLDAPs, "ldap configuration", true);
                if (newLDAPS != null) {
                    oa2Client.setLdaps(ldapConfigurationUtil.fromJSON(newLDAPS));
                }

            }

        } // end advanced options
        // CIL-1507 simplify cfg entry
        boolean doCfg = getPropertyHelp(keys.cfg(), "edit \"" + keys.cfg() + "\" (as JSON)? (y/n)", "n").equalsIgnoreCase("y");
        if (doCfg) {
            JSONObject newConfig = inputJSON(oa2Client.getConfig(), "client configuration");
            if (newConfig != null) {
                oa2Client.setConfig(newConfig);
            }
        }
    }

    protected List<String> processCommaSeparatedList(String key, String moniker, String defaultValue) throws IOException {
        return processCommaSeparatedList(key, null, moniker, defaultValue);
    }

    /**
     * Prompt for a comma separated list, parse it an return it. The moniker identifies what goes on the list,
     * the legalValues (if present) restrict the values to what is on that list.
     *
     * @param legalValues
     * @param moniker
     * @param defaultValue
     * @return
     * @throws IOException
     */
    protected List<String> processCommaSeparatedList(String key, List<String> legalValues, String moniker, String defaultValue) throws IOException {
        String rawValues = getPropertyHelp(key, "enter a comma separated list of " + moniker + ".", defaultValue);
        LinkedList<String> list = new LinkedList<>();
        if (rawValues.equals(defaultValue)) {
            list.add(defaultValue);
            return list;
        }
        LinkedList<String> omitted = new LinkedList<>();
        if (!(rawValues == null || rawValues.isEmpty())) {
            StringTokenizer stringTokenizer = new StringTokenizer(rawValues, ",");
            while (stringTokenizer.hasMoreTokens()) {
                String raw = stringTokenizer.nextToken().trim();
                if (legalValues != null) {
                    if (legalValues.contains(raw)) {
                        list.add(raw);
                    } else {
                        omitted.add(raw);
                    }
                } else {
                    list.add(raw);
                }
            }
        }
        if (!omitted.isEmpty()) {
            say("  omitted values:" + omitted);
        }
        return list;
    }

    @Override
    protected boolean supportsQDL() {
        return true;
    }

    @Override
    protected void showDeserializeHelp() {
        super.showDeserializeHelp();
        say("NOTE that for clients, the assumption is that you are supplying the hashed secret, not the actual secret.");
        say("If you need to create a hash of a secret, invoke the create_hash method on the secret");
    }

    public OA2ClientCommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
    }

    @Override
    protected boolean updateSingleValue(XMLMap map, String key) throws IOException {
        // Fixes CIL-1025 -- recognize config attribute as JSON at all times,
        // especially when it is null.
        String currentValue = map.getString(key);
        OA2ClientKeys keys = (OA2ClientKeys) getSerializationKeys();
        if (currentValue == null && key.equals(keys.cfg())) {
            map.put(key, "{}"); // empty JSON is still JSON.
        }

        return super.updateSingleValue(map, key);
    }

    public static String NO_STILE_FLAG = "-noStile";

    public void get_comment(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("get_comment [" + NO_STILE_FLAG + "- display the comment for a give object");
            say(NO_STILE_FLAG + " - do not show the stile (|) when printing comments");
            say("See also: set_comment");
            return;
        }
        Identifiable x = findItem(inputLine);
        if (x == null) {
            say("Object not found");
            return;
        }
        boolean noStile = inputLine.hasArg(NO_STILE_FLAG);
        OA2Client oa2Client = (OA2Client) x;
        JSONArray array;
        List<String> comments = oa2Client.getComment();
        if (comments == null || comments.isEmpty()) {
            say("(no comments)");
            return;
        }
        for (String comment : comments)
            say((noStile ? "" : "|") + comment);
    }

    public static String END_COMMENT_INPUT_CHAR = ".";
    public static String ABORT_COMMENT_INPUT_CHAR = ")";

    public void set_comment(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_comment - input a comment line by line");
            say("Note that input ends when the very first character on a line is a " + END_COMMENT_INPUT_CHAR);
            say("Note that if you want to abort, the first character on a line is a " + ABORT_COMMENT_INPUT_CHAR);
            say("See also: get_comment");
            return;
        }
        Identifiable x = findItem(inputLine);
        if (x == null) {
            say("Object not found");
            return;
        }
        OA2Client oa2Client = (OA2Client) x;

        say("Input your comment. Starting a line with a " + END_COMMENT_INPUT_CHAR + " ends input, " + ABORT_COMMENT_INPUT_CHAR + " aborts input.");
        List<String> comments = new ArrayList<>();
        String comment = readline();
        while (!comment.startsWith(END_COMMENT_INPUT_CHAR)) {
            if (comment.startsWith(ABORT_COMMENT_INPUT_CHAR)) {
                say("input aborted. returning...");
                return;
            }
            comments.add(comment);
            comment = readline();
        }
        oa2Client.setComment(comments);
        getStore().save(oa2Client);
    }

    public void resolve(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            sayi("resolve [id] - resolve a client from its prototypes (if any) and show it");
            sayi("See also: serialize");
            return;
        }
        Identifiable identifiable = findItem(inputLine);
        if (identifiable == null) {
            say("no such client");
            return;
        }
        OA2Client oa2Client = OA2ClientUtils.resolvePrototypes((ClientStore) getStore(), (OA2Client) identifiable);
        longFormat(oa2Client, true);
    }

    @Override
    protected void showSerializeHelp() {
        say("serialize  [-file path] [-resolve] index");
        sayi("Usage: XML serializes an object and either shows it on the ");
        sayi("   command line or put it in a file. Cf. deserialize.");
        sayi("-resolve - if this has prototypes, resolve them all and serialize the ");
        sayi("   resulting object");
        sayi("See also: deserialize.");
    }

    @Override
    public void serialize(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showSerializeHelp();
            return;
        }
        Identifiable x = findItem(inputLine);
        if (x == null) {
            say("object not found");
            return;
        }
        if (inputLine.hasArg("-resolve")) {
            x = OA2ClientUtils.resolvePrototypes((ClientStore) getStore(), (OA2Client) x);
        }
        serialize(inputLine, x);
    }

    public void ea_support(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("ea_support [arg] - show or toggle client extended attribute support");
            say(" if arg is missing, show the current value");
            say(" if arg is present it must be one of on|true or off|false");
            say("extended attributes are namespace qualified attributes that a client may");
            say("pass in and are simply forwarded to the scripting engine in the variable xas.");
            say("E.g.");
            say("A typical use would be to pass along the parameter oa4mp:/tokens/access/lifetime=900000");
            say("which would result in the value for xas. of ");
            say("{oa4mp:\n" +
                    "  {/tokens/access/lifetime:900000}\n" +
                    "}");
            say("in the QDL runtime environment. OA4MP does nothing with these except pass them through.");
            return;
        }
        Identifiable x = findItem(inputLine);
        if (x == null) {
            say("object not found");
            return;
        }
        OA2Client client = (OA2Client) x;
        if (!inputLine.hasArgs()) {
            say("has extended attribute support? " + ((OA2Client) x).hasExtendedAttributeSupport());
            return;
        }
        boolean enable = inputLine.getLastArg().equalsIgnoreCase("on") || inputLine.getLastArg().equalsIgnoreCase("true");
        boolean disable = inputLine.getLastArg().equalsIgnoreCase("off") || inputLine.getLastArg().equalsIgnoreCase("false");
        if (enable || disable) {
            if (enable) {
                client.setExtendedAttributeSupport(true);
                say("extended attribute support enabled");
            }
            if (disable) {
                client.setExtendedAttributeSupport(false);
                say("extended attribute support disabled");
            }
            getStore().save(client);
            return;
        } else {
            say("unrecognized option \"" + inputLine.getLastArg() + "\"");
        }
    }

    @Override
    public void bootstrap() throws Throwable {
        super.bootstrap();
        getHelpUtil().load("/help/client_help.xml");
    }

    public static String UUC_FLAG_TEST = "-test";
    public static String UUC_FLAG_CFG = "-cfg";
    public static String UUC_FLAG_FOUND = "-found";
    public static String UUC_FLAG_ENABLE = "-enable";

  /*  public void uuc(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("uuc [" +
                    UUC_FLAG_TEST + " on|true|off|false] [" +
                    UUC_FLAG_CFG + "] [" +
                    CL_OUTPUT_FILE_FLAG + " file] [" +
                    UUC_FLAG_FOUND + "] [" +
                    UUC_FLAG_ENABLE + "] = unused client cleanup. Run the client cleanup for this store");
            say(UUC_FLAG_TEST + " = (optional) turn on or off test mode. In test mode, the clients to delete");
            say("        are simply printed, not actually deleted.");
            say(UUC_FLAG_CFG + " = simply prints out the configuration, if any.");
            say(UUC_FLAG_FOUND + " = should the list of client ids that were found.");
            say(UUC_FLAG_ENABLE + " = manually enable this if it is disabled.");
            say(CL_OUTPUT_FILE_FLAG + " = write any output to the given file.");
            say("\nOne use pattern is to put the configuration into the server configuration file and only");
            say("run it manually in the CLI. In that case, set it to disabled and enable it here.");
            say("This will not run disabled configurations.");
            FormatUtil.printFormatListHelp(new BasicIO(), inputLine);
            return;
        }
        if (inputLine.hasArg(UUC_FLAG_CFG)) {
            if (getUucConfiguration() == null) {
                say("no config");
                return;
            }
            say(getUucConfiguration().toString(true));
            return;
        }
        boolean writeOutput = inputLine.hasArg(CL_OUTPUT_FILE_FLAG);
        String outputFilename = null;
        if (writeOutput) {
            outputFilename = inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG);
            inputLine.removeSwitchAndValue(CL_OUTPUT_FILE_FLAG);
        }
        boolean showFound = inputLine.hasArg(UUC_FLAG_FOUND);
        if (getUucConfiguration() == null) {
            say("UUC configuration not found");
            return;
        }
        if (inputLine.hasArg(UUC_FLAG_ENABLE)) {
            getUucConfiguration().enabled = inputLine.hasArg(UUC_FLAG_ENABLE);
            inputLine.removeSwitch(UUC_FLAG_ENABLE);
            say("UUC configuration" + (getUucConfiguration().enabled ? "enabled" : "disabled") + " . ");
            return;
        }
        if (!getUucConfiguration().enabled) {
            say("configuration disabled");
            return;
        }
        if (inputLine.hasArg(UUC_FLAG_TEST)) {
            String arg = inputLine.getNextArgFor(UUC_FLAG_TEST);
            if (arg.equalsIgnoreCase("on") || arg.equalsIgnoreCase("true")) {
                getUucConfiguration().testMode = true;
            }
            if (arg.equalsIgnoreCase("off") || arg.equalsIgnoreCase("false")) {
                getUucConfiguration().testMode = false;
            }

            inputLine.removeSwitchAndValue(UUC_FLAG_TEST);
        }
        BaseClientStore clientStore = (BaseClientStore) getStore();
        UUCResponse response = clientStore.unusedClientCleanup(getUucConfiguration());
        say("Stats are " + response);
        if (writeOutput) {
            FileWriter fw = new FileWriter(outputFilename);
            for (String x : response.found) {
                fw.write(x + "\n");
            }
            fw.flush();
            fw.close();
            say("output written to " + outputFilename);
        }
        if (showFound) {
            say("found ids are:");
            FormatUtil.formatList(inputLine, response.found);
        }
        say("There were " + response.found.size() + " clients found to remove");
    }
*/
    @Override
    protected BaseClient approvalMods(InputLine inputLine, BaseClient client) throws IOException {
        OA2Client oa2Client = (OA2Client) client;
        OA2ClientKeys keys = (OA2ClientKeys) getSerializationKeys();
        oa2Client.setStrictscopes(getPropertyHelp(keys.strictScopes(), "strict scopes?(y/n)", oa2Client.useStrictScopes() ? "y" : "n").equalsIgnoreCase("y"));
        return oa2Client;
    }

    public static String E_CREATE_FLAG = "-create";
    public static String E_LINK_FLAG = "-link";
    public static String E_LIST_FLAG = "-list";
    public static String E_LIST_AS_ARRAY_FLAG = "-array";
    public static String E_LIST_AS_JSON_FLAG = "-json";
    public static String E_LIST_AS_MULTILINE_FLAG = "-m";
    public static String E_UNLINK_FLAG = "-unlink";
    public static String E_ADMIN_ID_FLAG = "-adminID";

    protected void showErsatzHelp() {
        say("Create, link, unlink or list ersatz clients");
        say("ersatz " + E_CREATE_FLAG + " [new_id] [" + E_LINK_FLAG + "] [" + E_ADMIN_ID_FLAG + " admin_id] [provisioner_id] - create a new ersatz client, ");
        say("     optionally linking it to the provisioner. Note that if you do not supply an admin id and the provisioner is administered,");
        say("     then the new ersatz client will be added to the admin. If there is no admin, then none will be specified");
        say("     Finally, if the provisioner has multiple admins, this specifies which to use or the request will be rejected.");
        say("ersatz " + E_LIST_FLAG + " [" + E_LIST_AS_MULTILINE_FLAG + " | " + E_LIST_AS_ARRAY_FLAG + " | " + E_LIST_AS_JSON_FLAG + "] [provisioner_id] - list the ersatz clients associated with this provisioner");
        say("     Optionally list any chains as arrays, a json array or the (default) multi-line format");
        say("ersatz " + E_LINK_FLAG + " ersatz_id | [e0,e1,...] [" + E_ADMIN_ID_FLAG + " adminID] [provisioner_id]- link an existing ersatz client/chain to the current one");
        say("ersatz " + E_UNLINK_FLAG + " ersatz_id | [e0,e1,...] [" + E_ADMIN_ID_FLAG + " adminID] [provisioner_id] - unlink the ersatz client from this client. It does not do anything to the ersatz client.");
        say();
        say("Note that listing the ersatz clients lists the chains of them, so a typical output might be");
        say("client_id_1");
        say("  client_id_2");
        say("    client_id_3");
        say("client_id_1");
        say("  client_id_1a");
        say("    client_id_5");
        say("which means that for this client the chains are client_id_1->client_id_2->client_id_3 and ");
        say("client_is_1->client_id_1a->client_id_5.");
        say("Note that indenting sets off the chain, no indents means there is simply the client without others");
        say("Note that the " + E_LINK_FLAG + " and " + E_UNLINK_FLAG + " commands take either a single ersatz id");
        say("or an ordered chain (as a  list) of them. Note that if linking, each ersatz client will be added to the");
        say("admin's client list.");
    }

    public void ersatz(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showErsatzHelp();
            return;
        }
        boolean createClient = inputLine.hasArg(E_CREATE_FLAG);
        inputLine.removeSwitch(E_CREATE_FLAG);
        boolean hasAdminID = inputLine.hasArg(E_ADMIN_ID_FLAG);
        Identifier adminID = null;
        if (hasAdminID) {
            adminID = BasicIdentifier.newID(inputLine.getNextArgFor(E_ADMIN_ID_FLAG));
        }
        inputLine.removeSwitch(E_ADMIN_ID_FLAG);

        boolean listAsJSON = inputLine.hasArg(E_LIST_AS_JSON_FLAG);
        inputLine.removeSwitch(E_LIST_AS_JSON_FLAG);

        boolean listAsArray = inputLine.hasArg(E_LIST_AS_ARRAY_FLAG);
        inputLine.removeSwitch(E_LIST_AS_ARRAY_FLAG);

        boolean listAsMultiline = inputLine.hasArg(E_LIST_AS_MULTILINE_FLAG);
        inputLine.removeSwitch(E_LIST_AS_MULTILINE_FLAG);

        boolean linkClient = inputLine.hasArg(E_LINK_FLAG);
        List<Identifier> linkList = null;

        if (linkClient) {
            if (createClient) {
                // in this case, the flag means to link the newly created client, so
                // there is no chain.
            } else {
                if (inputLine.hasArgList(E_LINK_FLAG)) { // checks if it has a list as an argument
                    List<String> rawIDs = inputLine.getArgList(E_LINK_FLAG);
                    linkList = new ArrayList<>();
                    for (String s : rawIDs) {
                        linkList.add(BasicIdentifier.newID(s));
                    }
                } else {
                    linkList = new ArrayList<>();
                    linkList.add(BasicIdentifier.newID(inputLine.getNextArgFor(E_LINK_FLAG)));
                }
            }
            inputLine.removeSwitch(E_LINK_FLAG);
        }
        boolean unlinkClient = inputLine.hasArg(E_UNLINK_FLAG);
        if (linkClient && unlinkClient) {
            say("you cannot both link and unlink a client at the same time");
            return;
        }
        if (unlinkClient) {
            if (inputLine.hasArgList(E_UNLINK_FLAG)) {
                List<String> rawIDs = inputLine.getArgList(E_UNLINK_FLAG);
                linkList = new ArrayList<>();
                for (String s : rawIDs) {
                    linkList.add(BasicIdentifier.newID(s));
                }
            } else {
                linkList = new ArrayList<>();
                linkList.add(BasicIdentifier.newID(inputLine.getNextArgFor(E_UNLINK_FLAG)));
            }
            inputLine.removeSwitch(E_UNLINK_FLAG);
        }
        if (createClient) {
            // set errant switches correctly. I.e. if they pass this in and try to create, ignore it later
            unlinkClient = false;
        }
        boolean listClients = inputLine.hasArg(E_LIST_FLAG);
        inputLine.removeSwitch(E_LIST_FLAG);
        OA2Client provisioner = (OA2Client) findItem(inputLine);
        inputLine.removeSwitch(provisioner.getIdentifierString()); // trick. Remove ID by value if there.
        if (provisioner == null) {
            say("could not find the provisioner...");
            return;
        }
        if (adminID == null) {
            List<Identifier> admins = getPermissionsStore().getAdmins(provisioner.getIdentifier());
            if (1 < admins.size()) {
                say("ambiguous case: too many admins for this client. Cannot tell which to link to");
                return;
            }
            if (1 == admins.size()) {
                adminID = admins.get(0);
            }
            // otherwise, no such admin.
        }

        if (listClients) {
            if (provisioner == null) {
                say("no such client");
                return;
            }
            boolean arrayOutput = listAsArray || listAsJSON;
            if (!arrayOutput && !listAsMultiline) {
                listAsMultiline = true; // sets the default if nothing is specified
            }
            PermissionList pList = getPermissionsStore().getErsatzChains(adminID, provisioner.getIdentifier());
            for (Permission permission : pList) {
                JSONArray jsonArray = new JSONArray();
                String cliArray = "[";
                boolean firstPass = true;
                if (permission.canSubstitute()) {

                    List<Identifier> eChain = permission.getErsatzChain();
                    int indent = 0;
                    for (Identifier ee : eChain) {
                        if (listAsJSON) {
                            jsonArray.add(ee.toString());
                        }
                        if (listAsArray) {
                            if (firstPass) {
                                firstPass = false;
                            }
                            cliArray = cliArray + ee.toString();
                        }
                        if (listAsMultiline) {
                            say(StringUtils.getBlanks(2 * indent++) + ee);
                        }
                    }
                }
                if (listAsArray) {
                    say(cliArray + "]");
                }
                if (listAsJSON) {
                    say(jsonArray.toString());
                }
                if (listAsMultiline) {
                    say();
                }
            }

            return;
        }
        if (createClient) {
            OA2Client c = (OA2Client) getStore().create();
            if (0 < inputLine.getArgCount()) {
                // There is still an unsed argument. By process of elimination it is the requested new
                // id of the object. Reset it.
                c = (OA2Client) setIDFromInputLine(c, inputLine);
            }
            OA2Client createdClient = (OA2Client) create(c, ERSATZ_CREATE_MAGIC_NUMBER);
            if (createdClient == null) {
                return; // the user aborted the save.
            }
            if (linkClient) {
                linkList = new ArrayList<>();
                linkList.add(createdClient.getIdentifier());
                linkErsatz(provisioner, adminID, linkList);
                say("ersatz client linked, done.");
            } else {
                say("client created, not linked. done.");
            }
            return;
        }
        if (linkClient) {
            linkErsatz(provisioner, adminID, linkList);
            say("linking done!");
            return;
        }

        if (unlinkClient) {
            unlinkErsatz(provisioner, adminID, linkList);
            say("unlink done!");
            return;
        }
        say("unknown/missing option");
    }

    protected void linkErsatz(OA2Client provisioner, Identifier adminID, List<Identifier> ersatz) {

        for (Identifier id : ersatz) {
            // Check that the ersatz clients are administered by this admin and, if not
            // set them to be so.
            PermissionList pList = getPermissionsStore().get(adminID, id);
            OA2Client e = (OA2Client) getOA2SE().getClientStore().get(id);
            if (e != null) {
                e.setErsatzClient(true);
            }
            // no permissions means create new ones.
            if (pList.isEmpty()) {
                Permission newErsatzPermission = (Permission) getPermissionsStore().create();
                newErsatzPermission.setAdminID(adminID);
                newErsatzPermission.setClientID(id);
                newErsatzPermission.setApprove(true);
                newErsatzPermission.setCreate(true);
                newErsatzPermission.setDelete(true);
                newErsatzPermission.setRead(true);
                newErsatzPermission.setWrite(true);
                getPermissionsStore().save(newErsatzPermission);
            }
            PermissionList permissions = getPermissionsStore().getErsatzChains(adminID, provisioner.getIdentifier());
            if (!hasEChain(permissions, ersatz)) {
                Permission p = (Permission) getPermissionsStore().create();
                p.setAdminID(adminID);
                p.setClientID(provisioner.getIdentifier());
                p.setSubstitute(true);
                p.setErsatzChain(ersatz);
                getPermissionsStore().save(p);
            }
        }
    }

    protected boolean hasEChain(PermissionList permissions, List<Identifier> eChain) {
        if (permissions.isEmpty()) {
            return false;
        }
        for (Permission p : permissions) {
            if (p.canSubstitute()) {
                List<Identifier> eee = p.getErsatzChain();
                if (eee.size() != eChain.size()) {
                    continue;
                }
                for (int i = 0; i < eee.size(); i++) {
                    if (!eee.get(i).equals(eChain.get(i))) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    protected void unlinkErsatz(OA2Client provisioner, Identifier adminID, List<Identifier> ersatz) {
        PermissionList permissions = getPermissionsStore().getErsatzChains(adminID, provisioner.getIdentifier());
        for (Permission p : permissions) {
            List<Identifier> eChain = p.getErsatzChain();
            if (eChain.size() == ersatz.size()) {
                boolean notFound = true;
                for (int i = 0; i < eChain.size(); i++) {
                    if (!eChain.get(i).equals(ersatz.get(i))) {
                        notFound = false;
                        break;
                    }
                }
                if (notFound) {
                    getPermissionsStore().remove(p.getIdentifier());
                }
            }
        }
    }

    public static final int ERSATZ_CREATE_MAGIC_NUMBER = 1;

    @Override
    protected Identifiable preCreation(Identifiable identifiable, int magicNumber) {
        OA2Client client = (OA2Client) identifiable;
        if (magicNumber == ERSATZ_CREATE_MAGIC_NUMBER) {
            client.setErsatzClient(true);
            client.setExtendsProvisioners(isOk("extends the provisioners?"));
        }
        return client;
    }
    // Fixes https://github.com/ncsa/oa4mp/issues/163
    @Override
    protected void rmCleanup(Identifiable x) {
        super.rmCleanup(x);
        if (getStore().containsKey(x.getIdentifier())) { // double checks not removing a live record!
            sayi("client still active, cannot remove permissions");
            return;
        }

          List<Identifier> admins = getPermissionsStore().getAdmins(x.getIdentifier());
        // Fix https://github.com/ncsa/oa4mp/issues/174
        switch (admins.size()){
            case 0:
                // no admins, nothing to do.
                sayi("done");
                break;
            case 1:
                // Fix https://github.com/ncsa/oa4mp/issues/163
                PermissionList permissions = getPermissionsStore().get(admins.get(0), x.getIdentifier());
                getPermissionsStore().remove(permissions); // removes all the permission objects
                sayi("permissions removed:" + permissions.size());
                break;
            default:
                sayi("too many admins, remove permission manually and specify both admin and client ids");
        }
    }
}
