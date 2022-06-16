package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLJSONConfigUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalStoreCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.qdl.scripting.JSONScriptUtil;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import edu.uiuc.ncsa.security.util.scripting.ScriptingConstants;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine.CONFIG_TAG;
import static edu.uiuc.ncsa.qdl.scripting.JSONScriptUtil.SCRIPTS_TAG;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:24 PM
 */
public class OA2ClientCommands extends ClientStoreCommands {
    public OA2ClientCommands(MyLoggingFacade logger,
                             String defaultIndent,
                             Store clientStore,
                             ClientApprovalStoreCommands clientApprovalStoreCommands) {
        super(logger, defaultIndent, clientStore, clientApprovalStoreCommands);
    }


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
    public void print_help(InputLine inputLine) throws Exception {
        super.print_help(inputLine);
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
     * Do not call super on this method since the standard client tracks a public key file rather
     * than the hash of a secret string.
     *
     * @param identifiable
     */
    @Override
    public void extraUpdates(Identifiable identifiable) throws IOException {
        OA2Client client = (OA2Client) identifiable;
        String secret = client.getSecret();
        String input;
        boolean askForSecret = true;


        while (askForSecret) {
            input = getInput("enter a new secret or return to skip.", secret);
            if (isEmpty(input)) {
                sayi("Nothing entered. Client secret entry skipped.");
                break;
            }
            if (input.equals(secret)) {
                sayi(" Client secret entry skipped.");
                break;
            }
            // input is not empty.
            secret = DigestUtils.sha1Hex(input);
            client.setSecret(secret);
            askForSecret = false;
        }
        OA2Client oa2Client = (OA2Client) identifiable;
        if (isRefreshTokensEnabled()) {
            // so at this point the server actually allows for refresh tokens
            String NONE = "none";
            String rtString = oa2Client.isRTLifetimeEnabled() ? Long.toString(oa2Client.getRtLifetime() / 1000) : NONE;
            String rawLifetime = getInput("enter the refresh lifetime in sec.", rtString);

            if (rawLifetime == null || rawLifetime.length() == 0 || rawLifetime.toLowerCase().equals(NONE)) {
                oa2Client.setRtLifetime(0);
            } else {
                try {
                    oa2Client.setRtLifetime(Long.parseLong(rawLifetime) * 1000L);
                } catch (Throwable t) {
                    sayi("Sorry but \"" + rawLifetime + "\" is not a valid number. No change.");
                }
            }
        }
        boolean publicClient = oa2Client.isPublicClient();
        String rawPC = getInput("is this client public?", Boolean.toString(publicClient));
        if (rawPC != null && rawPC.toLowerCase().equalsIgnoreCase("y") || rawPC.toLowerCase().equalsIgnoreCase("yes")) {
            rawPC = "true";
        }
        try {
            boolean x = Boolean.parseBoolean(rawPC);
            oa2Client.setPublicClient(x);
        } catch (Throwable t) {
            sayi("Sorry, but unable to parse the response of \"" + rawPC + "\". No change.");
        }

        String issuer = getInput("enter the issuer (optional)", oa2Client.getIssuer());
        if (!isEmpty(issuer)) {
            oa2Client.setIssuer(issuer);
        }

        String signTokens = getInput("Enable ID token signing (true/false)?", Boolean.toString(oa2Client.isSignTokens()));
        if (!isEmpty(signTokens)) {
            try {
                oa2Client.setSignTokens(Boolean.parseBoolean(signTokens));
            } catch (Throwable t) {
                // do nothing.
                sayi("Unknown response of \"" + signTokens + "\". Must be \"true\" or \"false\", ignoring.");
            }
        }

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
        String scopes = getInput("enter a comma separated list of scopes. Scopes to this server will be rejected.", currentScopes);

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
        String uris = getInput("enter a comma separated list of callback uris. These must start with https or they will be ignored.", currentUris);

        if (!uris.isEmpty()) {
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
        JSON currentLDAPs = null;
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

        if (client.getLdaps() == null || client.getLdaps().isEmpty()) {
//            currentLDAPs = null;
        } else {
            // moving this here. If there are older LDAP configurations you can edit them, but can't add new ones.
            // These are officially not supported any longer.
            currentLDAPs = ldapConfigurationUtil.toJSON(client.getLdaps());
            JSONArray newLDAPS = (JSONArray) inputJSON(currentLDAPs, "ldap configuration", true);
            if (newLDAPS != null) {
                client.setLdaps(ldapConfigurationUtil.fromJSON(newLDAPS));
            }

        }
        boolean loadQDL = getInput("Load only a QDL script or edit the JSON? (q/j)", "j").equalsIgnoreCase("q");
        if (loadQDL) {
            JSONObject oldCfg = client.getConfig();
            JSONObject qdlcfg = loadQDLScript(oldCfg);
            if (qdlcfg == null) {
                // do nothing
            }

        } else {
            JSONObject newConfig = (JSONObject) inputJSON(client.getConfig(), "client configuration");
            if (newConfig != null) {
                client.setConfig(newConfig);
            }
        }
    }

    @Override
    protected boolean supportsQDL() {
        return true;
    }


    @Override
    protected JSONObject loadQDLScript(JSONObject currentConfig) throws IOException {
       /* The configuration is the entire qdl object , i.e.
          {"qdl":{"scripts":[...]}}
        */
        say("select one of the following ways to do this:");
        //  say("d - load a directory of scripts (advanced!)");
        say("e - edit a script with the line editor");
        say("f - read a script from a file");
        say("p - paste a QDL configuration");
//        say("w - start the QDL workspace");
        String option = readline().trim().toLowerCase();
        JSONObject result = null;
        switch (option) {
          /*  case "d":
                say("Sorry, that is not quite ready");
                break;*/
            case "e":
                ScriptSet scriptSet = QDLJSONConfigUtil.readScriptSet(currentConfig);
                QDLCLICommands qdlcliCommands = new QDLCLICommands(logger, scriptSet);
                CLIDriver driver = new CLIDriver(qdlcliCommands);
                driver.start();
                result = QDLJSONConfigUtil.scriptSetToJSON(qdlcliCommands.getScriptSet());
                break;
            case "f":
                say("Enter the name of a QDL script. Generally if the name is the same as the execution phase");
                say("You don't have to do anything else");
                say("phases are: " + ScriptingConstants.SRE_PHASES);
                say("So a file named " + ScriptingConstants.SRE_EXEC_INIT + ".qdl would be automatically run at initialization.");
                String fileName = getInput("Enter the file name", "");
                if (fileName.equals("")) {
                    say("Sorry, you did not enter a valid file name");
                }
                try {
                    // This creates a completely new configuration with only this script in it.
                    result = QDLJSONConfigUtil.createCfg(fileName);
                } catch (Throwable throwable) {
                    say("sorry, that didn't work:" + throwable.getMessage());
                    return null;
                }

                break;
            case "p":
                result = inputJSON(currentConfig, "QDL script"); // This shows the QDL tag, which is probably better
                break;
            //return  inputJSON(currentConfig.getJSONObject(QDLRuntimeEngine.CONFIG_TAG), "QDL script");
          /*  case "w":
                QDLWorkspace workspace = new QDLWorkspace(new WorkspaceCommands()));
                String args[] = new String[]{"-ext \"edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2QDLLoader\""};
                workspace.main(args);
*/
            default:
                say("sorry, i didn't understand that.");
                return null;
        }
        // If nothing happened, just return the original.
        if (result == null) {
            return currentConfig;
        }

            /*
            Now we process the result.
            They can
            * add a  single script, replaces  one or add if new
            * add a scripts object, replaces whole thing
            * paste a whole QDL configuration, replaces whole thing
            This MUST return a complete QDL configuration objeft like
            {"qdl":{.. lots of stuff ...}}
            This is called in StoreCommands2 and all it will do is replace the entry in toto.
            All decisions about what goes where are done here.
            And don't forget that the JSON library we use tends to makes tons of copies of things,
            so updating requires we reset the values. You cannot just get a JSON component and alter it.
             */
        if (result.containsKey(Scripts.SCRIPT)) {
            // They entered a single script. Add it
            JSONObject scripts = currentConfig.getJSONObject(CONFIG_TAG);
            // {"scripts":[]}
            scripts = JSONScriptUtil.addScript(scripts, result);
            // So we have a single scripts entry. There may be others in the config, so don't change them
            currentConfig.put(CONFIG_TAG, scripts);
        }
        if (result.containsKey(SCRIPTS_TAG)) {

            // replace entire scripts entry.
            currentConfig.put(CONFIG_TAG, result);

        }
        if (result.containsKey(CONFIG_TAG)) {
            // integrate it
            currentConfig.put(CONFIG_TAG, result.getJSONObject(CONFIG_TAG));
        }


        return currentConfig;

    }


    @Override
    protected void showDeserializeHelp() {
        super.showDeserializeHelp();
        say("NOTE that for clients, the assumption is that you are supplying the hashed secret, not the actual secret.");
        say("If you need to create a hash of a secret, invoke the create_hash method on the secret");
    }

    public OA2ClientCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    @Override
    protected boolean updateSingleValue(XMLMap map, String key) throws IOException {
        // Fixes CIL-1025 -- recognize config attribute as JSON at all times,
        // especially when it is null.
        String currentValue = map.getString(key);
        OA2ClientKeys keys = (OA2ClientKeys) getMapConverter().getKeys();
        if (currentValue == null && key.equals(keys.cfg())) {
            map.put(key, "{}"); // empty JSON is still JSON.
        }

        return super.updateSingleValue(map, key);
    }
     public static String NO_STILE_FLAG = "-noStile";
    public void get_comment(InputLine inputLine) throws Throwable {
        if(showHelp(inputLine)){
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
            say((noStile?"":"|")+comment);
    }
    public static String END_COMMENT_INPUT_CHAR = ".";
    public static String ABORT_COMMENT_INPUT_CHAR = ")";
    public void set_comment(InputLine inputLine) throws Throwable{
        if(showHelp(inputLine)){
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
        while(!comment.startsWith(END_COMMENT_INPUT_CHAR)){
            if(comment.startsWith(ABORT_COMMENT_INPUT_CHAR)){
                say("input aborted. returning...");
                return;
            }
            comments.add(comment);
            comment = readline();
        }
        oa2Client.setComment(comments);
        getStore().save(oa2Client);
    }

    public void resolve(InputLine inputLine)throws Exception{
        if(showHelp(inputLine)){
            sayi("resolve [id] - resolve a client and show it");
            sayi("See also: serialize");
            return;
        }
        Identifiable identifiable = findItem(inputLine);
        if(identifiable == null){
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
        if(inputLine.hasArg("-resolve")){
            x = OA2ClientUtils.resolvePrototypes((ClientStore) getStore(), (OA2Client) x);
        }
        serialize(inputLine, x);
    }
}
