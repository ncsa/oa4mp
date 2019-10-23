package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.cli.ExitException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval.Status.APPROVED;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.CLEAR_COMMAND;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.EXIT_COMMAND;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:24 PM
 */
public class OA2ClientCommands extends ClientStoreCommands {
    public OA2ClientCommands(MyLoggingFacade logger,
                             String defaultIndent,
                             Store clientStore,
                             ClientApprovalStore clientApprovalStore) {
        super(logger, defaultIndent, clientStore, clientApprovalStore);
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
    protected void longFormat(BaseClient identifiable, ClientApproval clientApproval) {
        OA2Client client = (OA2Client) identifiable;
        say("Client name=" + (client.getName() == null ? "(no name)" : client.getName()));
        sayi("identifier=" + client.getIdentifier());
        sayi("email=" + client.getEmail());
        // Fix for CIL-501 -- removed showing home and error uris here since they are also show by the super class.
        sayi("creation timestamp=" + client.getCreationTS());
        sayi("last modified timestamp=" + client.getLastModifiedTS());
        sayi("sign ID tokens?=" + client.isSignTokens());
        sayi("issuer=" + client.getIssuer());
        sayi("is public?=" + client.isPublicClient());
        if (clientApproval == null) {
            // if it is missing, then create on and mark it pending.
            clientApproval = (ClientApproval) getClientApprovalStore().create();
            clientApproval.setIdentifier(client.getIdentifier()); // or it won't associate it with the client...
            clientApproval.setStatus(ClientApproval.Status.PENDING);
            clientApproval.setApproved(false);
            getClientApprovalStore().save(clientApproval);
            //     sayi("no approval record exists.");

        }

        if (clientApproval.isApproved() && clientApproval.getStatus() != APPROVED) {
            clientApproval.setStatus(APPROVED);
        }
        switch (clientApproval.getStatus()) {
            case APPROVED:
                String approver = "(unknown)";
                if (clientApproval.getApprover() != null) {
                    approver = clientApproval.getApprover();
                }
                sayi("status=approved by " + approver);
                break;
            case NONE:
                sayi("status=none");
                break;
            case PENDING:
                sayi("status=pending");
                break;
            case DENIED:
                sayi("status=approval denied");
                break;
            case REVOKED:
                sayi("status=revoked");

        }
        if (client.getSecret() == null) {
            sayi("client secret: (none)");

        } else {
            sayi("client secret (hash):" + client.getSecret());
        }
        Collection<String> uris = client.getCallbackURIs();
        if (uris == null) {
            sayi("callback uris: (none)");
        } else {
            sayi("callback uris" + (uris.isEmpty() ? ":(none)" : ":"));
            for (String x : uris) {
                sayi("      " + x);
            }
        }
        Collection<String> scopes = client.getScopes();
        if (scopes == null) {
            sayi("scopes: (none)");
        } else {
            sayi("scopes" + (scopes.isEmpty() ? ":(none)" : ":"));
            for (String x : scopes) {
                sayi("      " + x);
            }
        }
        if (isRefreshTokensEnabled()) {
            sayi("refresh lifetime (sec): " + (client.isRTLifetimeEnabled() ? (client.getRtLifetime() / 1000) : "none"));
        }
        if (client.getLdaps() == null || client.getLdaps().isEmpty()) {
            sayi("ldap:(none configured.)");
        } else {
            sayi("LDAPS (warning-deprecated, use the config instead):");
            LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

            say(ldapConfigurationUtil.toJSON(client.getLdaps()).toString(2));

        }
        if (client.getConfig() == null || client.getConfig().isEmpty()) {
            sayi("config:(none)");
        } else {
            sayi("config:");
            sayi(client.getConfig().toString(2));
        }
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


    public void cb(InputLine inputLine) {
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



    protected void removeCB(OA2Client client, Collection<String> cbs) {
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
                    URI tempURI = URI.create(nextToken);
                    if (!tempURI.getScheme().equals("https")) {
                        say("Sorry but the protocol for \"" + nextToken + "\" is not supported. It must be https. Rejected.");
                    } else {
                        cbs.add(nextToken);
                    }
                } catch (Throwable t) {
                    say("Sorry but \"" + nextToken + "\" is not a valid URL. Skipped.");
                }
            }
        }
        return cbs;
    }

    protected void processDBAdd(OA2Client client, Collection<String> newArgs) {
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
    public void extraUpdates(Identifiable identifiable) {
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
                    oa2Client.setRtLifetime(Long.parseLong(rawLifetime)*1000L);
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
/*
                try {
                    URI uri = URI.create(raw);
                //    if (uri.getScheme().toLowerCase().equals("https")) {
                        list.add(raw);
                 //   } else {
                 //   }
                } catch (Throwable t) {
                    // do nothing. Just ignore illegal uris.
                    sayi("\"" + raw + "\" rejected -- illegal uri");
                }
*/
            }
            LinkedList<String> dudURIs = new LinkedList<>();
            List<String> foundURIs = null;
            try {
            foundURIs =    OA2ClientUtils.createCallbacks(rawCBs, dudURIs);
            }catch(IOException iox){
                say("Sorry, there was an error processing the uris:\"" + iox.getMessage() + "\"");
                return;
            }
            if(0 < dudURIs.size()){
                say(dudURIs.size() + " uris rejected:");
                for(String dud : dudURIs){
                    say("  " + dud);
                }
            }
            if(foundURIs == null){
                // This ***should** be impossible.
                say("There was an error processing the URIs");
                return;
            }
            oa2Client.setCallbackURIs(foundURIs);
        }
        JSON currentLDAPs = null;
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();

        if (client.getLdaps() == null || client.getLdaps().isEmpty()) {
            currentLDAPs = null;
        } else {
            currentLDAPs = ldapConfigurationUtil.toJSON(client.getLdaps());
        }
        JSONArray newLDAPS = (JSONArray) inputJSON(currentLDAPs, "ldap configuration", true);
        if (newLDAPS != null) {
            client.setLdaps(ldapConfigurationUtil.fromJSON(newLDAPS));
        }

        JSONObject newConfig = (JSONObject) inputJSON(client.getConfig(), "client configuration");
        if (newConfig != null) {
            client.setConfig(newConfig);
        }
    }

    protected JSON inputJSON(JSON oldJSON, String componentName) {
        return inputJSON(oldJSON, componentName, false);
    }

    /**
     * Allows for entering a new JSON object. This permits multi-line entry so formatted JSON can be cut and pasted
     * into the command line (as long as there are no blank lines). This will validate the JSON, print out a message and
     * check that you want to keep the new JSON. Note that you cannot overwrite the value of a configuration at this point
     * mostly as a safety feature. So hitting return or /exit will have the same effect of keeping the current value.
     *
     * @param oldJSON
     * @return null if the input is terminated (so retain the old object)
     */
    protected JSON inputJSON(JSON oldJSON, String componentName, boolean isArray) {
        if (oldJSON == null) {
            sayi("no current value for " + componentName);
        } else {
            sayi("current value for " + componentName + ":");
            say(oldJSON.toString(2));
        }
        sayi("Enter new JSON value. An empty line terminates input. Entering a line with " + EXIT_COMMAND + " will terminate input too.\n Hitting " + CLEAR_COMMAND + " will clear the contents of this.");
        String rawJSON = "";
        boolean redo = true;
        while (redo) {
            try {
                String inLine = readline();
                while (!isEmpty(inLine)) {
                    if (inLine.equals(CLEAR_COMMAND)) {
                        if (isArray) {
                            return new JSONArray();
                        } else {
                            return new JSONObject();
                        }
                    }
                    rawJSON = rawJSON + inLine;
                    inLine = readline();
                }
            } catch (ExitException x) {
                // ok, so user terminated input. This ends the whole thing
                return null;
            }
            // if the user just hits return with no input, do nothing. This lets them skip over unchanged entries.
            if (rawJSON.isEmpty()) {
                return null;
            }
            try {
                JSON json = null;
                if (isArray) {
                    json = JSONArray.fromObject(rawJSON);
                } else {
                    json = JSONObject.fromObject(rawJSON);
                }
                sayi("Success! JSON is valid.");
                return json;
            } catch (Throwable t) {
                sayi("uh-oh... It seems this was not a valid JSON object. The parser message reads:\"" + t.getMessage() + "\"");
                redo = isOk(getInput("Try to re-enter this?", "true"));
            }
        }

        return null;
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
}
