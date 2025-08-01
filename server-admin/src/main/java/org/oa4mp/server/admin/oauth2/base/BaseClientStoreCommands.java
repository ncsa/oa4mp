package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.ExitException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.Sortable;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.BaseClientKeys;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import org.oa4mp.delegation.server.storage.BaseClientStore;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static edu.uiuc.ncsa.security.util.cli.CLIDriver.CLEAR_BUFFER_COMMAND;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.EXIT_COMMAND;
import static org.oa4mp.delegation.server.storage.ClientApproval.Status.*;

/**
 * Commands for a base client store. This is the super class to several variations of clients.
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  1:03 PM
 */
public abstract class BaseClientStoreCommands extends OA4MPStoreCommands {

    public BaseClientStoreCommands(CLIDriver driver, String defaultIndent, Store clientStore,
                                   ClientApprovalStoreCommands clientApprovalStoreCommands) throws Throwable {
        super(driver, defaultIndent, clientStore);
        this.clientApprovalStoreCommands = clientApprovalStoreCommands;
        setSortable(new ClientSorter());
    }

    public BaseClientStoreCommands(CLIDriver driver, Store store) throws Throwable {
        super(driver, store);
    }

    // used internally to approve records.
    protected ClientApprovalStoreCommands clientApprovalStoreCommands = null;

    public ClientApprovalStore getClientApprovalStore() {
        return (ClientApprovalStore) clientApprovalStoreCommands.getStore();
    }


    protected JSON inputJSON(JSON oldJSON, String componentName) throws IOException {
        return inputJSON(oldJSON, componentName, false);
    }

    protected Sortable getSortable() {
        if (sortable == null) {
            sortable = new ClientSorter();
        }
        return sortable;
    }


    @Override
    public void print_help() throws Exception {
        super.print_help();
        say("--Utilities:");
        sayi("create_hash = create the hash of a password.");
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
    protected JSON inputJSON(JSON oldJSON, String componentName, boolean isArray) throws IOException {
        if (oldJSON == null) {
            sayi("no current value for " + componentName);
        } else {
            sayi("current value for " + componentName + ":");
            say(oldJSON.toString(2));
        }
        sayi("Enter new JSON value. An empty line terminates input. Entering a line with " + EXIT_COMMAND +
                " will terminate input too.\n Hitting " + CLEAR_BUFFER_COMMAND + " will clear the contents of this.");
        String rawJSON = "";
        boolean redo = true;
        while (redo) {
            try {
                String inLine = readline();
                while (!isEmpty(inLine)) {
                    if (inLine.equals(CLEAR_BUFFER_COMMAND)) {
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

    protected void showCreateHashHelp() {
        say("create_hash string | -file path");
        say("This will create a hash of the given string which is suitable for storing in the database.");
        say("If you specify a file, the entire content will be hashed.");
        say("Note that if there are emebedded blanks, you should enclose the entire argument in double quotes");
        say("E.g. \n\ncreate_hash my pass word");
        say("would just has \"word\", and to get the whole string you should enter");
        say("create_hash \"my pass word\"");
    }

    public void create_hash(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showCreateHashHelp();
            return;
        }

        String secret = null;
        if (inputLine.hasArg("-file")) {
            try {
                FileReader fis = new FileReader(inputLine.getArg(1 + inputLine.indexOf("-file")));
                StringBuffer sb = new StringBuffer();
                int i;
                while ((i = fis.read()) != -1) {
                    sb.append((char) i);
                }
                fis.close();
                secret = sb.toString();
            } catch (Throwable t) {
                say(" could not read file: " + t.getMessage());
                return;
            }
        } else {
            secret = inputLine.getLastArg();
        }
        say("creating hash of \"" + secret + "\"");
        say(DigestUtils.sha1Hex(secret));
    }

    @Override
    protected List<Identifiable> listEntries(List<Identifiable> entries, boolean lineList, boolean verboseList) {
        if (entries == null || entries.isEmpty()) {
            say("(no entries found)");
            return entries;
        }
        List<ClientApproval> approvals = getClientApprovalStore().getAll();
        HashMap<Identifier, ClientApproval> approvalMap = new HashMap<>();
        for (ClientApproval a : approvals) {
            approvalMap.put(a.getIdentifier(), a);
        }

        int i = 0;
        getSortable().setState(null);
        entries = getSortable().sort(entries);
        for (Identifiable x : entries) {
            ClientApproval tempA = approvalMap.get(x.getIdentifier());
            if (tempA == null) {
                tempA = new ClientApproval(x.getIdentifier());
                tempA.setStatus(ClientApproval.Status.NONE);
            }
            if (lineList) {
                if (i != 0) {
                    say("-----");
                }
                longFormat((BaseClient) x, tempA, false);
            } else {
                if (verboseList) {
                    longFormat((BaseClient) x, tempA, true);

                } else {
                    say(i + ". " + format((BaseClient) x, tempA));

                }
                i++;
            }
        }
        return entries;

    }

/*    @Override
    protected List<Identifiable> listAll(boolean useLongFormat, String otherFlags) {
        loadAllEntries();

        if (allEntries.isEmpty()) {
            say("(no entries found)");
            return allEntries;
        }
        List<ClientApproval> approvals = getClientApprovalStore().getAll();
        HashMap<Identifier, ClientApproval> approvalMap = new HashMap<>();
        for (ClientApproval a : approvals) {
            approvalMap.put(a.getIdentifier(), a);
        }

        int i = 0;
        getSortable().setState(otherFlags);
        allEntries = getSortable().sort(allEntries);
        for (Identifiable x : allEntries) {
            ClientApproval tempA = approvalMap.get(x.getIdentifier());
            if (tempA == null) {
                tempA = new ClientApproval(x.getIdentifier());
                tempA.setStatus(ClientApproval.Status.NONE);
            }
            if (useLongFormat) {
                if (i != 0) {
                    say("-----");
                }
                longFormat((BaseClient) x, tempA, false);
            } else {
                say(i + ". " + format((BaseClient) x, tempA));
            }
            i++;
        }
        return allEntries;
    }*/

    ClientApprovalStore clientApprovalStore;

    protected String format(BaseClient client, ClientApproval ca) {
        String rc = null;
        if (ca == null) {
            rc = "(?) " + client.getIdentifier() + " ";
        } else {
            boolean isApproved = ca != null && ca.isApproved();
            rc = "(" + (isApproved ? "Y" : "N") + ") " + client.getIdentifier() + " ";
        }
        String name = (client.getName() == null ? "no name" : client.getName());
        if (20 < name.length()) {
            name = name.substring(0, 20) + "...";
        }
        rc = rc + "(" + name + ")";
        rc = rc + " created on " + Iso8601.date2String(client.getCreationTS());
        return rc;

    }

    @Override
    protected String archiveFormat(Identifiable identifiable) {
        Long version = getStoreArchiver().getVersionNumber(identifiable.getIdentifier());
        int fieldWidth = Math.max(5, version.toString().length());
        BaseClient client = (BaseClient) identifiable;
        String caput = "";
        if (-1 < version) {
            caput = StringUtils.RJustify(version.toString(), fieldWidth);
        } else {
            caput = StringUtils.RJustify(" -- ", fieldWidth);
        }
        return "|" + caput + "| " + " archived on " + client.getLastModifiedTS();
    }

    @Override
    protected String format(Identifiable identifiable) {
        BaseClient client = (BaseClient) identifiable;
        ClientApproval ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        return format(client, ca);
    }

    @Override
    protected int longFormat(Identifiable identifiable, boolean isVerbose) {
        BaseClient client = (BaseClient) identifiable;
        ClientApproval ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        return longFormat(client, ca, isVerbose);
    }


    protected int longFormat(BaseClient client, ClientApproval clientApproval, boolean isVerbose) {
        int width = super.longFormat(client, isVerbose);
        if (clientApproval == null) {
            // if it is missing, then create on and mark it pending.
            clientApproval = (ClientApproval) getClientApprovalStore().create();
            clientApproval.setIdentifier(client.getIdentifier()); // or it won't associate it with the client...
            clientApproval.setStatus(ClientApproval.Status.PENDING);
            clientApproval.setApproved(false);
            getClientApprovalStore().save(clientApproval);
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
                say(formatLongLine("approved by", approver, width, isVerbose));
                break;
            case NONE:
                say(formatLongLine("status", "none", width, isVerbose));
                break;
            case PENDING:
                say(formatLongLine("status", "pending", width, isVerbose));
                break;
            case DENIED:
                say(formatLongLine("status", "approval denied", width, isVerbose));
                break;
            case REVOKED:
                say(formatLongLine("status", "revoked", width, isVerbose));

        }
        return width;
    }

    public static final String APPROVE_FLAG = "-approved";
    public static final String APPROVER_KEY = "-approver";

    protected void showApproveHelp() {
        clientApprovalStoreCommands.showApproveHelp();
    }


    public void approve(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }
        List<Identifiable> identifiables = findItem(inputLine);
        if (identifiables == null || identifiables.isEmpty()) {
            say("no clients found");
            return;
        }
        if (inputLine.getArgCount() == 0 && identifiables.size() == 1) {
            // legacy case: no other flags and a single id
            old_approve(inputLine, identifiables.get(0));
            return;
        }
        // set up the client approval mods once, then just switch client.
        ApprovalModsConfig approvalModsConfig = createApprovalModsConfig(inputLine, null, false);
        // It is easier for the user to think of turning them off, but got to get
        // the argument for the method right.
        String approver;
        if (inputLine.hasArg(APPROVER_KEY)) {
            approver = inputLine.getNextArgFor(APPROVER_KEY);
            inputLine.removeSwitchAndValue(APPROVER_KEY);
        } else {
            approver = getInput("Enter the name of the approver:", "");
            if (approver.isEmpty()) {
                say("approver required, exiting...");
                return;
            }
        }
        boolean approvalFlag = inputLine.hasArg(APPROVE_FLAG);
        Boolean doApproval = true;
        if (approvalFlag) {
            doApproval = inputLine.getBooleanNextArgFor(APPROVE_FLAG);
            if (doApproval == null) {
                say("unrecognized value for " + APPROVE_FLAG);
                return;
            }
            inputLine.removeSwitchAndValue(APPROVE_FLAG);
        }

        for (Identifiable identifiable : identifiables) {
            BaseClient client = (BaseClient) identifiable;
            approvalModsConfig.client = client;
            client = doApprovalMods(approvalModsConfig);
            ClientApprovalStoreCommands.setupApprovalRecord(getClientApprovalStore(), client.getIdentifier(), doApproval, approver);
            getStore().update(client);
        }
        say(identifiables.size() + " clients " + (doApproval ? "approved." : "unapproved."));
    }

    protected abstract ApprovalModsConfig createApprovalModsConfig(InputLine inputLine, BaseClient client, boolean doPrompt);

    protected void old_approve(InputLine inputLine, Identifiable identifiable) throws Throwable {
        // But everyone expects it to behave in the kludgy way for single approvals.
        BaseClient client = (BaseClient) identifiable;
        client = doApprovalMods(new ApprovalModsConfig(client, true));
        approve(client);
    }

    protected void approve(BaseClient client) throws IOException {

        // Fix https://github.com/ncsa/oa4mp/issues/109
        ClientApproval ca = null;
        if (getClientApprovalStore().containsKey(client.getIdentifier())) {
            ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        } else {
            ca = (ClientApproval) getClientApprovalStore().create();
            ca.setIdentifier(client.getIdentifier());
        }
        // now we have the right approval record for this identifier
        if (clientApprovalStoreCommands.approve(ca)) {
            getStore().save(client); // if they approve it, save any changes made in approvalMods
        }
    }

    /**
     * If there are modifications to the client before saving its approval (e.g.
     * admin clients should be prompted for QDL policy) put it here.
     *
     * @param approvalModsConfig
     * @return
     */
    protected BaseClient doApprovalMods(ApprovalModsConfig approvalModsConfig) throws IOException {
        return approvalModsConfig.client;
    }

    public static class ApprovalModsConfig {
        public ApprovalModsConfig(BaseClient client, boolean doPrompt) {
            this.client = client;
            this.doPrompt = doPrompt;
        }

        public BaseClient client;
        public boolean doPrompt = true;
    }

    @Override
    protected void rmCleanup(FoundIdentifiables x) {
        getClientApprovalStore().remove(x);// batch remove
        say(x.size() + " approvals removed");
    }


    public void approver_search(InputLine inputLine) {
        if (showHelp(inputLine)) {
            sayi("approver_search [ " + SEARCH_SHORT_REGEX_FLAG + "] approver [" + SEARCH_RESULT_SET_NAME + " rs_name]  - search for all " +
                    "approvals by a given approver.");
            sayi(SEARCH_RESULT_SET_NAME + " rs_name - save the result set under then name rs_name");
            sayi(SEARCH_SHORT_REGEX_FLAG + " - if present, treat the approver as a regex in the search.");
            sayi("Note that this searched for approvers restricted to current store. If you want");
            say("to search the entire set of approvers (and have regexes and dates available)");
            sayi("you should use the approvers component and do your searches there.");
            sayi("See also: search, status_search, rs");
            return;
        }


        boolean saveRS = inputLine.hasArg(SEARCH_RESULT_SET_NAME);
        String rsName = null;
        if (saveRS) {
            rsName = inputLine.getNextArgFor(SEARCH_RESULT_SET_NAME);
            inputLine.removeSwitchAndValue(SEARCH_RESULT_SET_NAME);
        }
        boolean isRegex = inputLine.hasArg(SEARCH_REGEX_FLAG) || inputLine.hasArg(SEARCH_SHORT_REGEX_FLAG);
        inputLine.removeSwitch(SEARCH_REGEX_FLAG);
        inputLine.removeSwitch(SEARCH_SHORT_REGEX_FLAG);
        if (0 == inputLine.getArgCount()) {
            say("missing approver. exiting...");
            return;
        }
        String approver = inputLine.getLastArg();
        ClientApprovalKeys caKeys = (ClientApprovalKeys) getClientApprovalStore().getMapConverter().getKeys();
        //List<Identifier> ids = ((BaseClientStore) getStore()).getByApprover(approver, getClientApprovalStore());
        List<Identifiable> approvals = getClientApprovalStore().search(caKeys.approver(), approver, isRegex);
        int i = 0;

        List<String> fields = new ArrayList<>();
        fields.add(caKeys.identifier());
        fields.add(caKeys.approver());

        if (saveRS) {
            // Remove it any same named from the client's saved result sets.
            RSRecord rsRecord = new RSRecord(approvals, caKeys.allKeys());
            getResultSets().put(rsName, rsRecord);
            say("stored " + approvals.size() + " results.");
        } else {
            clientApprovalStoreCommands.printRS(inputLine, approvals, fields, null);
        }
    }

    public void status_search(InputLine inputLine) {
        if (showHelp(inputLine)) {
            sayi("status_search [-size] [" + SEARCH_RESULT_SET_NAME + " rs_name] status - search for all clients with the given status");
            sayi(SEARCH_RESULT_SET_NAME + " rs_name - save the result set under the given name");
            say("-size = just return the number of clients found in the search.");
            sayi("status - the status. Allowed ones are");
            sayi(StringUtils.RJustify(APPROVED.getStatus(), 10) + " or a = approved");
            sayi(StringUtils.RJustify(DENIED.getStatus(), 10) + " or d = denied");
            sayi(StringUtils.RJustify(NONE.getStatus(), 10) + " or n = none");
            sayi(StringUtils.RJustify(PENDING.getStatus(), 10) + " or p = pending");
            sayi(StringUtils.RJustify(REVOKED.getStatus(), 10) + " or r = revoked");
            say("E.g.");
            sayi("status_search -rs my_pending p");
            say("would search for all pending approvals and save them in the result set named my_pending");
            say("See also: search, approver_search, rs");
            return;
        }

        boolean sizeOnly = inputLine.hasArg("-size");
        inputLine.removeSwitch("-size");
        boolean saveRS = inputLine.hasArg(SEARCH_RESULT_SET_NAME);
        String rsName = null;
        if (saveRS) {
            rsName = inputLine.getNextArgFor(SEARCH_RESULT_SET_NAME);
            inputLine.removeSwitchAndValue(SEARCH_RESULT_SET_NAME);
        }
        String rawStatus = inputLine.getLastArg();
        switch (rawStatus) {
            case "a":
                rawStatus = APPROVED.getStatus();
                break;
            case "d":
                rawStatus = DENIED.getStatus();
                break;
            case "n":
                rawStatus = NONE.getStatus();
                break;
            case "p":
                rawStatus = PENDING.getStatus();
                break;
            case "r":
                rawStatus = REVOKED.getStatus();
                break;
            default:
                say("unknown status: " + rawStatus);
                return;
        }
        BaseClientStore clientStore = (BaseClientStore) getStore();
        List<Identifier> ids = clientStore.getByStatus(rawStatus, getClientApprovalStore());

        if (sizeOnly) {
            say("there are " + ids.size() + " clients with the status " + rawStatus);
            return;
        }
        List<Identifiable> acs = new ArrayList<>(ids.size());
        int i = 0;
        BigDecimal bd = new BigDecimal(Math.ceil(Math.log10(ids.size())));
        int numberWidth = bd.intValue() + 1;
        for (Identifier id : ids) {
            // We have to have an Identifiable to stash, but do not want to e.g. suck in
            // a huge amount of information from the database. So we just get the ids and
            // create a placeholder. We can do this since we control this.
            acs.add((Identifiable) getStore().get(id));
            if (!saveRS) {
                say(StringUtils.RJustify((i++) + ".", numberWidth) + " " + id.toString());
            }
        }


        if (saveRS) {
            // Remove it any same named from the client's saved result sets.
            if (getResultSets().containsKey(rsName)) {
                getResultSets().remove(rsName);
                say("warning: overwriting existing client result set \"" + rsName + "\"");
            }
            say("got " + acs.size() + " results");
            getResultSets().put(rsName, new RSRecord(acs, getMapConverter().getKeys().allKeys()));
            return;
        }
        say();
        say(acs.size() + " clients with status " + rawStatus);
    }

    /**
     * CARS = <b>C</b>lient <b>A</b>pproval <b>R</b>esult <b>S</b>et. Return true if the given name is stored as a result
     * set for client approvals.
     *
     * @param name
     * @return
     */
    protected boolean isCARS(String name) {
        return clientApprovalStoreCommands.getResultSets().containsKey(name);
    }


/*
    @Override
    public void rs(InputLine inputLine) throws Throwable {
        // Have to take into account if the result set is for a set of approvals.
        if (inputLine.hasArg(RS_SHOW_ACTION)) {
            String name = inputLine.getLastArg();

            if (isCARS(name)) {
                clientApprovalStoreCommands.rs(inputLine);
                return;
            }
        }
        if (inputLine.hasArg(RS_CLEAR_ACTION)) {
            clientApprovalStoreCommands.setResultSets(new HashMap());
            inputLine.removeSwitch(RS_CLEAR_ACTION);
        }
        if (inputLine.hasArg(RS_REMOVE_ACTION)) {
            String name = inputLine.getLastArg();
            if (isCARS(name)) {
                clientApprovalStoreCommands.getResultSets().remove(name);
                return;
            }
        }
        if (inputLine.hasArg(RS_LIST_INFO_ACTION)) {
            // List lists all things, so no test about where the rs is stored.
            clientApprovalStoreCommands.rs(inputLine);
            inputLine.removeSwitch(RS_LIST_INFO_ACTION);
        }
        super.rs(inputLine);
    }
*/

/*    @Override
    public void rm(InputLine inputLine) throws Throwable {
        FoundIdentifiables ids = findItem(inputLine);
        if (ids == null) {
            say("no objects found");
            return;
        }
        if (ids.isRS()) {
            if (!"Y".equals(readline("Getting ready to remove " + ids.size() + " entries. Proceed?(Y/n)"))) {
                say("aborted");
                return;
            }
            getClientApprovalStore().remove(ids);
            getStore().remove(ids);

            say("done!");
            return;
        }

        super.rm(inputLine); // removes exactly the client
    }*/

    public void password(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("password [byte_count] - create a new random password and show its hash. ");
            say("if 0 < byte_count is given, then that will be the number of bytes in the password");
            say("The default is 64 bytes if this is omitted");
            say("E.g. from the clients component (results will vary):");
            say("  clients>password 32\n" +
                    "  password : dmYJJZo82JUPq4ZhAM3zVWWQHjE2A9rEdqeHxRtT-d4\n" +
                    "      hash : 2f11426429bb7ef99d8162d4e0b3a865c2ef796c");
            return;

        }
        int count = 64;
        SecureRandom random = new SecureRandom();
        switch (inputLine.getArgCount()) {
            case 0:
                break;
            case 1:
                try {
                    count = Integer.parseInt(inputLine.getLastArg());
                } catch (Throwable t) {
                    // do nothing
                    say("Could not parse the argument \"" + inputLine.getLastArg() + "\"");
                    return;

                }
                break;
            default:
                say("Sorry, too many arguments");
                return;
        }
        byte[] b = new byte[count];
        random.nextBytes(b);
        String password = org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(b);
        say("password : " + password);
        say("    hash : " + DigestUtils.sha1Hex(password));

    }

    public static String RESET_SECRET_SIZE_FLAG = "-size";
    public static String RESET_SECRET_NEW_FLAG = "-new";

    public static int RESET_SECRET_DEFAULT_SIZE = 64;

    public void reset_secret(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("reset_secret [" + RESET_SECRET_NEW_FLAG + " password] [" + RESET_SECRET_SIZE_FLAG + " byte_count] index");
            say("resets the current secret. This creates the hash of the new password.");
            say(RESET_SECRET_SIZE_FLAG + " = create a random secret with the given number of bytes.");
            say(RESET_SECRET_NEW_FLAG + " = explicitly give the secret and hash it.");
            say("If you specify both a secret and a size, the size is ignored.");
            say("No parameters mean a random secret of " + RESET_SECRET_DEFAULT_SIZE + " bytes (" + (RESET_SECRET_DEFAULT_SIZE * 8) + " bits) is created.");
            say("The password and secret are always printed.");
            printIndexHelp(true);
            say("\nE.g. setting the password, be sure to put it in quotes to get the whole thing:\n");
            say("clients>reset_secret " + RESET_SECRET_NEW_FLAG + " \"miarzy doats and dozey doats\"");
            say("  password : miarzy doats and dozey doats");
            say("      hash : 4d6e44b6ddceeccfe15e2f67f356cc09bbcec411");
            return;
        }

        int size = RESET_SECRET_DEFAULT_SIZE;
        boolean hasSize = inputLine.hasArg(RESET_SECRET_SIZE_FLAG);
        if (hasSize) {
            String x = inputLine.getNextArgFor(RESET_SECRET_SIZE_FLAG);
            inputLine.removeSwitchAndValue(RESET_SECRET_SIZE_FLAG);
            try {
                size = Integer.parseInt(x);
            } catch (Throwable t) {
                say("sorry, could not interpret a size of \"" + x + "\". aborting...");
                return;
            }
            if (size <= 0) {
                say("sorry,  size of \"" + size + "\" must be positive. aborting...");
                return;
            }
        }

        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("no client found.");
        }
        if (!identifiables.isSingleton()) {
            say("only a single object is supported for this operation");
            return;
        }
        String secret = null;
        boolean hasPassword = inputLine.hasArg(RESET_SECRET_NEW_FLAG);
        if (hasPassword) {
            secret = inputLine.getNextArgFor(RESET_SECRET_NEW_FLAG);
            inputLine.removeSwitchAndValue(RESET_SECRET_NEW_FLAG);
        }

        BaseClient client = (BaseClient) identifiables.get(0);

        if (!hasPassword) {
            byte[] y = new byte[size];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(y);
            secret = Base64.encodeBase64URLSafeString(y);
        }


        if (StringUtils.isTrivial(secret)) {
            say("sorry but could not determine a secret for client '" + client.getIdentifier() + "'");  // test just in case.
            return;
        }
        String hash = DigestUtils.sha1Hex(secret);
        client.setSecret(hash);
        getStore().save(client);
        if (-1 < secret.indexOf(" ")) {
            // If there are blanks, put quotes around it.
            secret = "\"" + secret + "\"";
        }
        say("client_id : " + client.getIdentifierString());
        say("   secret : " + secret);
        say("     hash : " + hash);

    }

    @Override
    public void create(InputLine inputLine) throws IOException {
        BaseClient client = (BaseClient) actualCreate(inputLine, DEFAULT_MAGIC_NUMBER);
        if (client == null) {
            return;
        }
        if (isOk(readline("approve this client [y/n]?"))) {
            approve(client);
        }
    }

    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {
        BaseClient client = (BaseClient) identifiable;
        BaseClientKeys keys = (BaseClientKeys) getSerializationKeys();

        client.setName(getPropertyHelp(keys.name(), "enter name", client.getName()));
        client.setEmail(getPropertyHelp(keys.email(), "enter email", client.getEmail()));
        String keyOrSecret = getPropertyHelp(keys.secret(), "enter a key, secret or URI (k|s|u) or return to skip", "");
        switch (keyOrSecret) {
            case "k":
            case "K":
                getPublicKeyFile(client, keys);
                break;
            case "s":
            case "S":
                getSecret(client, keys);
                break;
            case "u":
            case "U":
                String rr = getPropertyHelp(keys.jwksURI(), "  enter JWKS uri", "");
                if (isEmpty(rr)) {
                    say("   skipped");
                } else {
                    client.setJwksURI(URI.create(rr));
                }
                break;
            case "":
                break;
            default:
                say("unknown option \"" + keyOrSecret + "\"");
                // do nothing.
        }

    }

    /**
     * Prompt the user for a secret, hashing the result.
     */
    protected void getSecret(BaseClient client, BaseClientKeys keys) throws IOException {
        String input = getPropertyHelp(keys.secret(), "  enter a new secret or return to skip.", client.getSecret());
        if (isEmpty(input)) {
            return;
        }
        // input is not empty.
        String secret = DigestUtils.sha1Hex(input);
        client.setSecret(secret);
    }

    protected void getPublicKeyFile(BaseClient client, BaseClientKeys keys) throws IOException {
        String input;
        String fileNotFoundMessage = INDENT + "...uh-oh, I can't find that file. Please enter it again";
        String secret = client.getSecret();

        if (!isEmpty(secret)) {
            secret = secret.substring(0, Math.min(25, secret.length())) + "...";
        }
        boolean askForFile = true;
        while (askForFile) {
            input = getPropertyHelp(keys.jwks(), "  enter full path and file name of public key", secret);
            if (isEmpty(input)) {
                return;
            }
            if (input.equals(secret)) {
                sayi(" public key entry skipped.");
                return;
            }
            // if this is not the default value, then this *should* be the name of a file.
            File f;
            if (input != null) {
                f = new File(input);
                if (!f.exists()) {
                    say(fileNotFoundMessage);
                    continue;
                }
                try {
                    client.setJWKS(JSONWebKeyUtil.fromJSON(f));
                    askForFile = false;
                } catch (Throwable e) {
                    say("error reading file \"" + input + "\", try again");
                    return;
                }
            }
        }
    }

    // Fix https://github.com/ncsa/security-lib/issues/45 and https://github.com/ncsa/oa4mp/issues/243
    @Override
    public ChangeIDRecord doChangeID(Identifiable identifiable, Identifier newID, boolean updatePermissions) {
        ChangeIDRecord changeIDRecord = super.doChangeID(identifiable, newID, updatePermissions);
        // find the approval and update it now
        ClientApproval clientApproval = (ClientApproval) getClientApprovalStore().get(changeIDRecord.oldID);
        if (clientApproval == null) {
            clientApproval = (ClientApproval) getClientApprovalStore().create();
        } else {
            getClientApprovalStore().remove(changeIDRecord.oldID);
        }
        clientApproval.setIdentifier(newID);
        getClientApprovalStore().save(clientApproval);
        return changeIDRecord;
    }
}
