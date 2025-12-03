package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.server.server.config.LDAPConfigurationUtil;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.server.storage.uuc.UUCConfiguration;
import org.oa4mp.server.admin.oauth2.base.ClientApprovalStoreCommands;
import org.oa4mp.server.admin.oauth2.base.ClientStoreCommands;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionList;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;
import org.oa4mp.server.loader.oauth2.servlet.OA2ClientUtils;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientKeys;

import java.io.IOException;
import java.util.*;

import static org.oa4mp.server.loader.oauth2.storage.clients.OA2Client.USE_SERVER_DEFAULT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:24 PM
 */
public class OA2ClientCommands extends ClientStoreCommands {
    public OA2ClientCommands(CLIDriver driver,
                             String defaultIndent,
                             Store clientStore,
                             ClientApprovalStoreCommands clientApprovalStoreCommands,
                             PermissionsStore permissionsStore) throws Throwable {
        super(driver, defaultIndent, clientStore, clientApprovalStoreCommands);
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
        say("cb -add [https://foo1, https://foo2,https://foo3 /oa4mp:client/id/234234234234]");
        say("\nThis adds the three urls to the current list for the client with the given id.");
        printIndexHelp(true);
    }


    public void cb(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showCBHelp();
            return;
        }

        boolean gotOne = false;
        OA2Client client = (OA2Client) findSingleton(inputLine);
        if (inputLine.hasArg("-add")) {
            gotOne = true;
            List<String> cbs = inputLine.getArgList("-add");
            client.getCallbackURIs().addAll(cbs);
            getStore().save(client);
            return;
        }
        if (inputLine.hasArg("-rm")) {
            gotOne = true;
            Collection<String> cbs = inputLine.getArgList("-rm");
            Collection<String> storedCBs = client.getCallbackURIs();
            List<String> target = new ArrayList<>(storedCBs.size());
            for (String cb : storedCBs) {
                if (!cbs.contains(cb)) {
                    target.add(cb);
                }
            }
            client.setCallbackURIs(target);
            getStore().save(client);
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
            if (rtGracePeriod == OA2CFConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DISABLED) {
                rawLifetime = RT_DISABLED;
            } else {
                if (rtGracePeriod == OA2CFConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT) {
                    rawLifetime = DEFAULT_SERVER_VALUE;
                } else {
                    if (rtGracePeriod == OA2CFConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_NOT_CONFIGURED) {
                        // not configured means no action has been taken, so set to default
                        rawLifetime = Long.toString(OA2CFConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DEFAULT);
                    } else {
                        rawLifetime = Long.toString(rtGracePeriod);
                    }
                }
            }
            rawLifetime = getPropertyHelp(keys.rtGracePeriod(), "  enter grace period in sec., " + RT_DISABLED + ", or " + DEFAULT_SERVER_VALUE, rawLifetime);
            switch (rawLifetime) {
                case RT_DISABLED:
                    oa2Client.setRtGracePeriod(OA2CFConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_DISABLED);
                    break;
                case DEFAULT_SERVER_VALUE:
                    oa2Client.setRtGracePeriod(OA2CFConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT);
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
     * Prompt for a comma separated list, parse it and return it. The moniker identifies what goes on the list,
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
        if (StringUtils.isTrivial(rawValues)) {
            return list; // nix to do and don't return a list of blanks or some such.
        }
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

    /*@Override
    protected boolean supportsQDL() {
        return true;
    }*/

    @Override
    protected void showDeserializeHelp() {
        super.showDeserializeHelp();
        say("NOTE that for clients, the assumption is that you are supplying the hashed secret, not the actual secret.");
        say("If you need to create a hash of a secret, invoke the create_hash method on the secret");
    }

    public OA2ClientCommands(CLIDriver driver, Store store) throws Throwable {
        super(driver, store);
    }

    @Override
    protected Object updateSingleValue(XMLMap map, String key) throws IOException {
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
            say("get_comment [" + NO_STILE_FLAG + "] index- display the comment for a give object");
            say(NO_STILE_FLAG + " - do not show the stile (|) when printing comments");
            printIndexHelp(false);
            say("See also: set_comment");
            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("Object not found");
            return;
        }
        boolean noStile = inputLine.hasArg(NO_STILE_FLAG);
        for (Identifiable identifiable : identifiables) {
            OA2Client oa2Client = (OA2Client) identifiable;
            say(oa2Client.getIdentifierString());
            List<String> comments = oa2Client.getComment();
            if (comments == null || comments.isEmpty()) {
                say("(no comments)");
                return;
            }
            for (String comment : comments) {
                say((noStile ? "" : "|") + comment);
            }
            if (1 < identifiables.size()) {
                say(""); // spacer
            }

        }
    }

    public static String END_COMMENT_INPUT_CHAR = ".";
    public static String ABORT_COMMENT_INPUT_CHAR = ")";

    public void set_comment(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_comment index- input a comment line by line");
            say("Note that input ends when the very first character on a line is a " + END_COMMENT_INPUT_CHAR);
            say("Note that if you want to abort, the first character on a line is a " + ABORT_COMMENT_INPUT_CHAR);
            printIndexHelp(true);
            say("See also: get_comment");
            return;
        }

        OA2Client oa2Client = (OA2Client) findSingleton(inputLine);

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

    public void resolve(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            sayi("resolve index - resolve a client from its prototypes (if any) and show it");
            printIndexHelp(false);
            sayi("See also: serialize");
            return;
        }
        OA2Client oa2Client = OA2ClientUtils.resolvePrototypes((ClientStore) getStore(), (OA2Client) findSingleton(inputLine));
        longFormat(oa2Client, true);
    }

    @Override
    protected void showSerializeHelp() {
        say("serialize  [-file path] [-resolve] index");
        sayi("Usage: XML serializes an object and either shows it on the ");
        sayi("   command line or put it in a file. Cf. deserialize.");
        sayi("-resolve - if this has prototypes, resolve them all and serialize the ");
        sayi("   resulting object");
        printIndexHelp(true);
        sayi("See also: deserialize.");
    }

    @Override
    public void serialize(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showSerializeHelp();
            return;
        }

        Identifiable identifiable = findSingleton(inputLine, "client not found");
        if (inputLine.hasArg("-resolve")) {
            identifiable = OA2ClientUtils.resolvePrototypes((ClientStore) getStore(), (OA2Client) findSingleton(inputLine));
        }
        serialize(inputLine, identifiable);
    }

    public void ea_support(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("ea_support [arg] index - show or toggle client extended attribute support");
            say(" if arg is missing, show the current value");
            say(" if arg is present it must be one of on|true or off|false");
            say("extended attributes are namespace qualified attributes that a client may");
            say("pass in and are simply forwarded to the scripting engine in the variable xas.");
            say("EA support is not stored in a regular DB column but ina special structure.");
            say("This utility is the only to reliably interact with it.");
            say("The effect is to toggle whether EAs in a request are passed along to the runtime envirnoment");
            say("or not. You do not set EAs here, but let the policy handle what it gets.");
            printIndexHelp(false);
            say("E.g.");
            say("A typical use would be to pass along the parameter oa4mp:/tokens/access/lifetime=900000");
            say("which would result in the value for xas. of ");
            say("{oa4mp:\n" +
                    "  {/tokens/access/lifetime:900000}\n" +
                    "}");
            say("in the QDL runtime environment. OA4MP does nothing with these except pass them through.");
            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("object not found");
            return;
        }
        if (!inputLine.hasArgs()) {
            for (Identifiable identifiable : identifiables) {
                if(identifiables.isRS()){
                    identifiable = (Identifiable) getStore().get(identifiable.getIdentifier());
                }
                say("(" + ((OA2Client) identifiable).hasExtendedAttributeSupport() + ")  " + identifiable.getIdentifierString());
            }
            return;
        }
        String action = "";
        final String ACTION_ENABLE = "enabled";
        final String ACTION_DISABLE = "disabled";
        if (inputLine.getLastArg().equalsIgnoreCase("on") || inputLine.getLastArg().equalsIgnoreCase("true")) {
            action = ACTION_ENABLE;
        } else {
            if (inputLine.getLastArg().equalsIgnoreCase("off") || inputLine.getLastArg().equalsIgnoreCase("false")) {
                action = ACTION_DISABLE;
            } else {
                action = inputLine.getLastArg();
            }
        }

            for (Identifiable identifiable : identifiables) {
                if(identifiables.isRS()){
                    identifiable = (Identifiable) getStore().get(identifiable.getIdentifier());
                }
                OA2Client client = (OA2Client) identifiable;
                switch (action) {
                    case ACTION_ENABLE:
                        client.setExtendedAttributeSupport(true);
                        break;
                    case ACTION_DISABLE:
                        client.setExtendedAttributeSupport(false);
                        break;
                    default:
                        say("unknown action \"" + action + "\", aborting");
                        return;

                }
                getStore().save(client);
            }
            say(identifiables.size() + " clients ea_support " + action);
    }


    @Override
    public void initHelp() throws Throwable {
        super.initHelp();
        getHelpUtil().load("/help/client_help.xml");
    }

    protected ApprovalModsConfig createApprovalModsConfig(InputLine inputLine, BaseClient client, boolean doPrompt) {
        boolean useStrictScopes = !inputLine.hasArg(USE_NONSTRICT_SCOPES);
        inputLine.removeSwitch(USE_NONSTRICT_SCOPES);
        return new OA2ClientApprovalMods(client, doPrompt, useStrictScopes);
    }

    public static class OA2ClientApprovalMods extends ApprovalModsConfig {
        public OA2ClientApprovalMods(BaseClient client, boolean doPrompt, boolean useStrictScopes) {
            super(client, doPrompt);
            this.useStrictScopes = useStrictScopes;
        }

        public boolean useStrictScopes = true;
    }

    @Override
    protected BaseClient doApprovalMods(ApprovalModsConfig approvalModsConfig) throws IOException {
        OA2Client oa2Client = (OA2Client) approvalModsConfig.client;
        if (approvalModsConfig.doPrompt) {
            OA2ClientKeys keys = (OA2ClientKeys) getSerializationKeys();
            oa2Client.setStrictscopes(getPropertyHelp(keys.strictScopes(), "strict scopes?(y/n)", oa2Client.useStrictScopes() ? "y" : "n").equalsIgnoreCase("y"));
        } else {
            oa2Client.setStrictscopes(((OA2ClientApprovalMods) approvalModsConfig).useStrictScopes);
        }
        return oa2Client;
    }

    public static final String USE_NONSTRICT_SCOPES = "-nonstrict";

    @Override
    protected void showApproveHelp() {
        say("approve item -- interactively approve a single client");
        say("approve [" + APPROVE_FLAG + " true | false] [" + USE_NONSTRICT_SCOPES + " ] " + APPROVER_KEY + " username item --  approve/unapprove a result set");
        say(USE_NONSTRICT_SCOPES + " = if present, grant the client non-strict scopes. Default si strict scopes.");
        say(APPROVE_FLAG + " = true (default), set the client as approved. If false, unapprove it.");
        say(APPROVER_KEY + " userName = (required) the name of the approver. If missing you will be prompted.");
        printIndexHelp(false);
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
        printIndexHelp(true);
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
        OA2Client provisioner = (OA2Client) findSingleton(inputLine);
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
            OA2Client e = (OA2Client) getEnvironment().getClientStore().get(id);
            if (e != null) {
                if(!e.isErsatzClient()) {
                    // just in case they created it without setting this.
                    e.setErsatzClient(true);
                   getStore().save(e);
                }
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
        if (eChain == null || permissions.isEmpty()) {
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
    protected void rmCleanup(FoundIdentifiables foundIdentifiables) {
        super.rmCleanup(foundIdentifiables);
        int adminCount = 0;
        int permissionCount = 0;
        int skippedCount = 0;
        for (Identifiable x : foundIdentifiables) {
            List<Identifier> admins = getPermissionsStore().getAdmins(x.getIdentifier());
            // Fix https://github.com/ncsa/oa4mp/issues/174
            switch (admins.size()) {
                case 0:
                    // no admins, nothing to do.
                    skippedCount++;
                    break;
                case 1:
                    // Fix https://github.com/ncsa/oa4mp/issues/163
                    PermissionList permissions = getPermissionsStore().get(admins.get(0), x.getIdentifier());
                    getPermissionsStore().remove(permissions); // removes all the permission objects
                    sayi("permissions removed:" + permissions.size());
                    adminCount++;
                    permissionCount = permissions.size() + permissionCount;
                    break;
                default:
                    skippedCount++;
                    sayi("too many admins for \"" + x.getIdentifierString() + "\". Remove permission manually and specify both admin and client ids");
            }
        }
        say("admins removed: " + adminCount + ", total permissions removed: " + permissionCount + ", skipped (not administered): " + skippedCount);
    }

    // Fix https://github.com/ncsa/oa4mp/issues/224
    public void service_client(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("service_client [on | true | off | false] index query or set if this client is a service client.");
            say("A service client is a client that is run by a service, typically this replaces the authorization ");
            say("leg of OAuth and is a token request. The two major RFC's that cover this are");
            say("RFC 7523, which specifies using keys generally too and");
            say("RFC 6749 §4.4, the client credentials flow");
            printIndexHelp(false);
            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("Sorry, client not found");
            return;
        }
        if (inputLine.getArgCount() == 0) {
            for (Identifiable identifiable : identifiables) {
                OA2Client client = (OA2Client) identifiable;
                say("client " + client.getIdentifierString() + (client.isServiceClient() ? " is" : " is not") + " a service client");
            }
            return;
        }


        Boolean newValue = null;
        if (inputLine.hasArg("true") || inputLine.hasArg("on")) {
            newValue = true;
        }
        if (inputLine.hasArg("false") || inputLine.hasArg("off")) {
            newValue = false;
        }
        if (newValue == null) {
            say("unknown value");
            return;
        }
        for (Identifiable identifiable : identifiables) {
            OA2Client client = (OA2Client) identifiable;
            boolean oldValue = client.isServiceClient();
            if (oldValue == newValue) {
                say("client " + client.getIdentifierString() + " already has " + (newValue ? "on" : "off"));
                continue;
            }
            client.setServiceClient(newValue);
            getStore().save(client);
            say("client " + client.getIdentifierString() + " has been set to " + (newValue ? "on" : "off"));
        }
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        // update client IDs
        List<Permission> permissions = getEnvironment().getPermissionStore().getByClientID(oldID);
        int updateCount = permissions.size();
        updateP(oldID, newID, copy, false, permissions);
        permissions = getEnvironment().getPermissionStore().getByErsatzID(oldID);
        // now to repeat this for ersatzIDs
        updateCount = updateCount + permissions.size();
        updateP(oldID, newID, copy, true, permissions);
        return updateCount;
    }

    /**
     * Returns the number of actual updates.
     *
     * @param newID
     * @param copyOnly
     * @param doErsatzID
     * @param permissions
     * @return
     */
    private int updateP(Identifier oldID,
                        Identifier newID,
                        boolean copyOnly,
                        boolean doErsatzID,
                        List<Permission> permissions) {
        int count = 0;
        if (!copyOnly) {
            // Do not just copy the permissions with the new ID, remove the old ones.
            getEnvironment().getPermissionStore().remove(permissions);
        }
        for (Permission p : permissions) {
            if (doErsatzID) {
                // The call to the store to get the chain may return extra items, since
                // the chain is JSON. This double checks we are only actually altering
                // permissions that actually need it.
                if (p.getErsatzChain().contains(oldID)) {
                    int ndx = p.getErsatzChain().indexOf(oldID);
                    p.getErsatzChain().set(ndx, newID); // order must be preserved!!
                    getEnvironment().getPermissionStore().save(p); // need batch mode for this?
                    count++;
                }
            } else {
                p.setClientID(newID);
                getEnvironment().getPermissionStore().save(p); // need batch mode for this?
                count++;
            }
        }
        return count;
    }
}
