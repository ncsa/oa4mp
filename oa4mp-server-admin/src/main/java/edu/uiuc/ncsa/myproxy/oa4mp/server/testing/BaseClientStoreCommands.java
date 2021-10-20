package edu.uiuc.ncsa.myproxy.oa4mp.server.testing;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalStoreCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientSorter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.server.storage.BaseClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;
import edu.uiuc.ncsa.security.util.cli.ExitException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval.Status.*;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.CLEAR_BUFFER_COMMAND;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.EXIT_COMMAND;

/**
 * Commands for a base client store. This is the super class to several variations of clients.
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  1:03 PM
 */
public abstract class BaseClientStoreCommands extends StoreCommands2 {

    public BaseClientStoreCommands(MyLoggingFacade logger, String defaultIndent, Store clientStore,
                                   ClientApprovalStoreCommands clientApprovalStoreCommands) {
        super(logger, defaultIndent, clientStore);
        this.clientApprovalStoreCommands = clientApprovalStoreCommands;
        setSortable(new ClientSorter());
    }

    public BaseClientStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    // used internally to approve records.
    protected ClientApprovalStoreCommands clientApprovalStoreCommands = null;

    public ClientApprovalStore getClientApprovalStore() {
        return (ClientApprovalStore) clientApprovalStoreCommands.getStore();
    }


    protected JSON inputJSON(JSON oldJSON, String componentName) throws IOException {
        return inputJSON(oldJSON, componentName, false);
    }

    @Override
    public void print_help(InputLine inputLine) throws Exception {
        super.print_help(inputLine);
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
                say("Error: could not read file: " + t.getMessage());
                return;
            }
        } else {
            secret = inputLine.getLastArg();
        }
        say("creating hash of \"" + secret + "\"");
        say(DigestUtils.sha1Hex(secret));
    }

    @Override
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
    }

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


    protected void showApproveHelp() {
        clientApprovalStoreCommands.showApproveHelp();
    }

    public void approve(InputLine inputLine) throws IOException {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }

        BaseClient client = (BaseClient) findItem(inputLine);
        ClientApproval ca = null;
        if (getClientApprovalStore().containsKey(client.getIdentifier())) {
            ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        } else {
            ca = (ClientApproval) getClientApprovalStore().create();
            ca.setIdentifier(client.getIdentifier());
        }
        // now we have the right approval record for this identifier
        clientApprovalStoreCommands.approve(ca);

    }

    @Override
    public boolean update(Identifiable identifiable) throws IOException {

        BaseClient client = (BaseClient) identifiable;

        String newIdentifier = null;

        info("Starting client update for id = " + client.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");

        newIdentifier = getInput("enter the identifier", client.getIdentifierString());
        boolean removeCurrentClient = false;
        Identifier oldID = client.getIdentifier();

        // no clean way to do this.
        client.setName(getInput("enter the name", client.getName()));
        client.setEmail(getInput("enter email", client.getEmail()));
        // set file not found message.
        extraUpdates(client);
        sayi("here is the complete client:");
        longFormat(client);
        if (!newIdentifier.equals(client.getIdentifierString())) {
            //  sayi2(" remove client with id=\"" + client.getIdentifier() + "\" [y/n]? ");
            removeCurrentClient = isOk(readline(" remove client with id=\"" + client.getIdentifier() + "\" [y/n]? "));
            client.setIdentifier(BasicIdentifier.newID(newIdentifier));
        }
        //  sayi2("save [y/n]?");
        if (isOk(readline("save [y/n]?"))) {
            //getStore().save(client);
            if (removeCurrentClient) {
                info("removing client with id = " + oldID);
                getStore().remove(client.getIdentifier());
                sayi("client with id " + oldID + " removed. Be sure to save any changes.");
            }
            sayi("client updated.");
            info("Client with id " + client.getIdentifierString() + " saving...");

            return true;
        }
        sayi("client not updated, losing changes...");
        info("User terminated updates for client with id " + client.getIdentifierString());
        return false;
    }

    @Override
    protected void rmCleanup(Identifiable x) {
        if (!getStore().containsKey(x.getIdentifier())) {
            sayi("Removing approval record");
            info("Removing approval record for id=" + x.getIdentifierString());
            getClientApprovalStore().remove(x.getIdentifier());
            sayi("Done. Client approval with id = " + x.getIdentifierString() + " has been removed from the store");
            info("Client record removed for id=" + x.getIdentifierString());
        }
    }


    public void approver_search(InputLine inputLine) {
        if (showHelp(inputLine)) {
            sayi("approver_search [ " + SEARCH_RESULT_SET_NAME + " rs_name] approver  - search for all " +
                    "approvals by a given approver.");
            sayi(SEARCH_RESULT_SET_NAME + " rs_name - save the result set under then name rs_name");
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
        String approver = inputLine.getLastArg();

        List<Identifier> ids = ((BaseClientStore) getStore()).getByApprover(approver, getClientApprovalStore());
        List<Identifiable> acs = new ArrayList<>();
        int i = 0;
        for (Identifier id : ids) {
            // We have to have an Identifiable to stash, but do not want to e.g. suck in
            // a huge amount of information from the database. So we just get the ids and
            // create a placeholder. We can do this since we control this.
            ClientApproval ca = new ClientApproval(id);
            ca.setApprover(approver);
            acs.add(ca);
        }
        ClientApprovalKeys caKeys = (ClientApprovalKeys) getClientApprovalStore().getMapConverter().getKeys();
        List<String> fields = new ArrayList<>();
        fields.add(caKeys.identifier());
        fields.add(caKeys.approver());

        if (saveRS) {
            // Remove it any same named from the client's saved result sets.
            if (getResultSets().containsKey(rsName)) {
                getResultSets().remove(rsName);
                say("warning: overwriting existing client result set \"" + rsName + "\"");
            }
            clientApprovalStoreCommands.getResultSets().put(rsName, new RSRecord(acs, fields));
            say("got " + acs.size() + " results.");
        }else{
            clientApprovalStoreCommands.printRS(inputLine, acs, fields,null);
        }
    }

    public void status_search(InputLine inputLine) {
        if (showHelp(inputLine)) {
            sayi("status_search [" + SEARCH_RESULT_SET_NAME + " rs_name] status - search for all clients with the given status");
            sayi(SEARCH_RESULT_SET_NAME + " rs_name - save the result set under the given name");
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
        }
        BaseClientStore clientStore = (BaseClientStore) getStore();
        List<Identifier> ids = clientStore.getByStatus(rawStatus, getClientApprovalStore());

        List<Identifiable> acs = new ArrayList<>();
        int i = 0;
        for (Identifier id : ids) {
            // We have to have an Identifiable to stash, but do not want to e.g. suck in
            // a huge amount of information from the database. So we just get the ids and
            // create a placeholder. We can do this since we control this.
            ClientApproval ca = new ClientApproval(id);
            ca.setStatus(ClientApproval.Status.resolveByStatusValue(rawStatus));
            acs.add(ca);
        }
        ClientApprovalKeys caKeys = (ClientApprovalKeys) getClientApprovalStore().getMapConverter().getKeys();
        List<String> fields = new ArrayList<>();
        fields.add(caKeys.identifier());
        fields.add(caKeys.status());

        if (saveRS) {
            // Remove it any same named from the client's saved result sets.
            if (getResultSets().containsKey(rsName)) {
                getResultSets().remove(rsName);
                say("warning: overwriting existing client result set \"" + rsName + "\"");
            }
            say("got " + acs.size() + " results");
            clientApprovalStoreCommands.getResultSets().put(rsName, new RSRecord(acs, fields));
        }else{
            clientApprovalStoreCommands.printRS(inputLine, acs, fields, null);
        }
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

    @Override
    public void rs(InputLine inputLine) throws Exception {
        // Have to take into account if the result set is for a set of approvals.
        if (inputLine.hasArg(RS_SHOW_KEY)) {
            String name = inputLine.getLastArg();
            if (isCARS(name)) {
                clientApprovalStoreCommands.rs(inputLine);
                return;
            }
        }
        if (inputLine.hasArg(RS_CLEAR_KEY)) {
            clientApprovalStoreCommands.setResultSets(new HashMap());
        }
        if (inputLine.hasArg(RS_REMOVE_KEY)) {
            String name = inputLine.getLastArg();
            if (isCARS(name)) {
                clientApprovalStoreCommands.getResultSets().remove(name);
                return;
            }
        }
        if (inputLine.hasArg(RS_LIST_KEY)) {
            // List lists all things, so no test about where the rs is stored.
            clientApprovalStoreCommands.rs(inputLine);
        }
        super.rs(inputLine);
    }

    @Override
    public void rm(InputLine inputLine) throws IOException {
        if (inputLine.hasArg(SEARCH_RESULT_SET_NAME)) {
            String name = inputLine.getNextArgFor(SEARCH_RESULT_SET_NAME);
            RSRecord rsRecord = null;
            // get the right result set.
            if (clientApprovalStoreCommands.getResultSets().containsKey(name)) {
                rsRecord = clientApprovalStoreCommands.getResultSets().get(name);
            } else {
                rsRecord = resultSets.get(name);
            }
            if (rsRecord == null) {
                say("no such stored result.");
                return;
            }
            if (!"Y".equals(readline("Getting ready to remove " + rsRecord.rs.size() + " entries. Proceed?(Y/n)"))) {
                say("aborted");
                return;
            }
            getClientApprovalStore().remove(rsRecord.rs);
            getStore().remove(rsRecord.rs);

            say("done!");
            // now we have to remove all of the identifiers from both the
            return;
        }

        super.rm(inputLine);
    }
}
