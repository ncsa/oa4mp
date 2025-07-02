package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;

import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/22/13 at  1:51 PM
 */
public class ClientApprovalStoreCommands extends OA4MPStoreCommands {

    public static final String SHOW_UNAPPROVED_FLAG = "-n";


    public ClientApprovalStoreCommands(CLIDriver driver, String defaultIndent, Store store) throws Throwable {
        super(driver, defaultIndent, store);
    }

    public ClientApprovalStoreCommands(CLIDriver driver, Store store) throws Throwable {
        super(driver, store);
    }


    @Override
    protected String format(Identifiable identifiable) {
        if (identifiable == null) return "(null)";
        ClientApproval ca = (ClientApproval) identifiable;
        String statusString = "?";
        switch (ca.getStatus()) {
            case APPROVED:
                statusString = "A";
                break;
            case DENIED:
                statusString = "D";
                break;
            case REVOKED:
                statusString = "R";
                break;
            case PENDING:
            case NONE:
        }
        String x = "(" + statusString + ") " + ca.getIdentifierString();
        if (ca.isApproved() || ca.getStatus() == ClientApproval.Status.APPROVED) {
            x = x + " by \"" + ca.getApprover() + "\" on " + ca.getApprovalTimestamp();
        }
        return x;
    }

    @Override
    public String getName() {
        return "  approvals";
    }

    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        ClientApproval clientApproval = (ClientApproval) identifiable;
        ClientApprovalKeys keys = (ClientApprovalKeys) getSerializationKeys();
        info("Starting update for client approval id=" + identifiable.getIdentifierString());
        sayi("Enter the information for the client approval");
        clientApproval.setApprover(getPropertyHelp(keys.approver(), "name of the approver", clientApproval.getApprover()));
        // Fix https://github.com/ncsa/oa4mp/issues/168
        clientApproval.setApprovalTimestamp(new Date());
        boolean isapproved = isOk(getPropertyHelp(keys.approved(), "set approved?", clientApproval.isApproved() ? "y" : "n"));
        if (isapproved) {
            clientApproval.setApproved(true);
            clientApproval.setStatus(ClientApproval.Status.APPROVED);
        } else {
            clientApproval.setApproved(false);
            switch (clientApproval.getStatus()) {
                case NONE:
                case PENDING:
                    clientApproval.setStatus(ClientApproval.Status.DENIED);
                    break;
                case APPROVED:
                    clientApproval.setStatus(ClientApproval.Status.REVOKED);
                    break;
                case REVOKED:
                case DENIED:
                    // no change in either case.
            }
        }
        sayi("save changes [y/n]?");
        if (isOk(readline())) {
            say(clientApproval.toString());
            return true;
        }
        sayi("save cancelled");
        info("Approval update cancelled for id=" + clientApproval.getIdentifierString());
        return false;
    }
    public void showApproveHelp() {
        say("approve index");
        say("This is the simple case of approving a client or set of them.");
        say("If you need to set the status to something other than 'approved',");
        say("use the set_status command.");
        say("Some components may prompt you for changes to the client as well.");
        say("The approval record will be for that client");
        printIndexHelp(false);
        say("\nSee also: set_status");
    }

    public void approve(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }
        int pass = 0;
        int fail = 0;
        boolean isapproved = isOk(getInput("set approved?", "y"));
        String approver = getInput("approver", "");
        FoundIdentifiables identifiables = findItem(inputLine);
        for (Identifiable identifiable : identifiables) {
            if(approve((ClientApproval) identifiable, isapproved, approver)){
                pass++;
            }else{
                fail++;
            }
        }
        say("Approved " + pass + ", denied " + fail);
    }

    public void set_status(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_status [new_status] index - this will set the status for the given/current record(s).");
            say("This is more reliable than simply updating the status property manually.");
            say("If new_status is given, then it will be set to that and the previous status displayed.");
            say("If new_status is missing, you will be prompted. Allowed values for new_status are");
            printIndexHelp(false);
            say("a | approved");
            say("d | denied");
            say("n | none");
            say("p | pending");
            say("r | revoked");
            say("\nand any value not on this list is rejected.");
            return;
        }
        FoundIdentifiables item = findItem(inputLine);
        if (item == null) {
            say("sorry, no record found.");
            return;
        }
        String newStatus = null;
        if (inputLine.getArgCount() == 0) {
            newStatus = getInput("enter new status", "a");
        } else {
            newStatus = inputLine.getLastArg();
        }
        for (Identifiable i : item) {
            ClientApproval approval = (ClientApproval) i;
            if(item.isRS()){
                // Result sets are static and should supply the identifier. Don't just
                // use the result set since that may overwrite other changes during save.
                approval = (ClientApproval) getStore().get(approval.getIdentifierString());
            }
            switch (newStatus) {
                case "a":
                case "approved":
                    approval.setStatus(ClientApproval.Status.APPROVED);
                    approval.setApproved(true);
                    break;
                case "d":
                case "denied":
                    approval.setStatus(ClientApproval.Status.DENIED);
                    approval.setApproved(false);
                    break;
                case "n":
                case "none":
                    approval.setStatus(ClientApproval.Status.NONE);
                    approval.setApproved(false);
                    break;
                case "p":
                case "pending":
                    approval.setStatus(ClientApproval.Status.PENDING);
                    approval.setApproved(false);
                    break;
                case "r":
                case "revoked":
                    approval.setStatus(ClientApproval.Status.REVOKED);
                    approval.setApproved(false);
                    break;
                default:
                    say("unrecognized status \"" + newStatus + "\".");
                    return;
            }
            getStore().save(approval);
        }
        say("done!");
    }

    /**
     * @param ca
     * @return true if saved.
     * @throws IOException
     */
    public boolean approve(ClientApproval ca) throws IOException {
        boolean isapproved = isOk(getInput("set approved?", ca.isApproved() ? "y" : "n"));
        String approver = getInput("approver", ca.getApprover());
       return  approve(ca, isapproved, approver);
    }

    /**
     * For thoses cases where the record needs to me fetched or created then set to the right values.
     * This and {@link #setupApprovalRecord(ClientApproval, boolean, String)} are called in this class
     * and are exposed as static methods to be called by other classes to central approvals.
     * This does do the save of this record since it has the logic to invoke {@link Store#update(Identifiable)}
     * versus {@link Store#save(Identifiable)}
     * @param identifier
     * @param isapproved
     * @param approver
     * @throws IOException
     */
    public static ClientApproval setupApprovalRecord(ClientApprovalStore caStore,
                                                     Identifier identifier,
                                                     boolean isapproved,
                                                     String approver) throws IOException {
        ClientApproval ca;
        boolean wasCreated = false;
        if(caStore.containsKey(identifier)){
            ca = (ClientApproval) caStore.get(identifier);
        }else{
            ca = (ClientApproval) caStore.create();
            ca.setIdentifier(identifier);
            wasCreated = true;
        }
        setupApprovalRecord(ca, isapproved, approver);
        if(wasCreated){
            caStore.save(ca);
        }else{
            caStore.update(ca);
        }
        return ca;
    }
    protected boolean approve(ClientApproval ca, boolean isapproved, String approver) throws IOException {
        setupApprovalRecord(ca, isapproved, approver);


        if (isOk(readline("save this approval record [y/n]?"))) {
            getStore().save(ca);
            sayi("approval saved");
            info("Approval for id = " + ca.getIdentifierString() + " saved");
            return true;
        }
        sayi("approval was not saved.");
        info("Approval cancelled for id=" + ca.getIdentifierString());
        return false;
    }

    /**
     * Does the work of setting the approval status, approver etc. Does not save it.
     * @param ca
     * @param isapproved
     * @param approver
     */
    public static void setupApprovalRecord(ClientApproval ca, boolean isapproved, String approver) {
        ca.setApprover(approver);
        if (isapproved) {
            ca.setApproved(true);
            ca.setStatus(ClientApproval.Status.APPROVED);
        } else {
            ca.setApproved(false);
            switch (ca.getStatus()) {
                case NONE:
                case PENDING:
                    ca.setStatus(ClientApproval.Status.DENIED);
                    break;
                case APPROVED:
                    ca.setStatus(ClientApproval.Status.REVOKED);
                    break;
                case REVOKED:
                case DENIED:
                    // no change in either case.
            }
        }
    }

    protected void show(boolean showApproved, String regex) throws Exception {
        say("showing " + (showApproved ? "" : "un") + "approved entries");
        List<ClientApproval> approvals = getStore().getAll();
        java.util.regex.Pattern p = null;
        java.util.regex.Matcher m;
        if (!StringUtils.isTrivial(regex)) {
            p = java.util.regex.Pattern.compile(regex);
        }

        int i = 0;
        for (ClientApproval ca : approvals) {
            if (p != null) {
                m = p.matcher(ca.getIdentifierString());
                if (!m.matches()) {
                    continue;
                }
            }
            if (showApproved) {
                if (ca.isApproved()) {
                    say(format(ca));
                    i++;
                }
            } else {
                if (!ca.isApproved()) {
                    say(format(ca));
                    i++;
                }
            }
        }
        say(i + (showApproved ? " " : " un") + "approved entries found");
    }


    public void show(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("show [" + SHOW_UNAPPROVED_FLAG + "] [" + SEARCH_SHORT_REGEX_FLAG + " regex]");
            sayi("Show either all the approved or unapproved records");
            sayi(SHOW_UNAPPROVED_FLAG + " - show only unapproved records");
            sayi(SEARCH_SHORT_REGEX_FLAG + " - apply the regular expression to the identifier");
            say("E.g.");
            sayi("show " + SEARCH_SHORT_REGEX_FLAG + " qdl.*");
            sayi("shows all approved clients whose identifier starts with qdl");
            sayi("show " + SHOW_UNAPPROVED_FLAG + " " + SEARCH_SHORT_REGEX_FLAG + " qdl.*");
            sayi("shows all UNapproved clients whose identifier starts with qdl");
        }
        boolean showApproved = !inputLine.hasArg(SHOW_UNAPPROVED_FLAG);
        inputLine.removeSwitch(SHOW_UNAPPROVED_FLAG);
        String regex = null;
        if (inputLine.hasArg(SEARCH_SHORT_REGEX_FLAG)) {
            regex = inputLine.getNextArgFor(SEARCH_SHORT_REGEX_FLAG);
            inputLine.removeSwitchAndValue(SEARCH_SHORT_REGEX_FLAG);
        }
        show(showApproved, regex);
    }


    @Override
    protected void initHelp() throws Throwable {
        super.initHelp();
        getHelpUtil().load("/help/approver_help.xml");
    }

    @Override
    public void change_id(InputLine inputLine) throws Throwable {
        say("Changing IDs for client approvals is not supported since the client shares the same id. ");
        say("Change the id of the client and the approvals will be updated automatically.");
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        throw new UnsupportedOperationException("Not supported for approvals.");
    }
}
