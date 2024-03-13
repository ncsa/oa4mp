package edu.uiuc.ncsa.myproxy.oauth2.base;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/22/13 at  1:51 PM
 */
public class ClientApprovalStoreCommands extends StoreCommands2 {

    public static final String SHOW_UNAPPROVED_FLAG = "-n";


    public ClientApprovalStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) throws Throwable {
        super(logger, defaultIndent, store);
    }

    public ClientApprovalStoreCommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
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
        ClientApprovalKeys keys = (ClientApprovalKeys)getSerializationKeys();
        info("Starting update for client approval id=" + identifiable.getIdentifierString());
        sayi("Enter the information for the client approval");
        clientApproval.setApprover(getPropertyHelp(keys.approver(),"name of the approver", clientApproval.getApprover()));
        // Fix https://github.com/ncsa/oa4mp/issues/168
        clientApproval.setApprovalTimestamp(new Date());
        boolean isapproved = isOk(getPropertyHelp(keys.approved(),"set approved?", clientApproval.isApproved() ? "y" : "n"));
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
        say("This is the simple case of approving a client.");
        say("If you need to set the status to something other than 'approved',");
        say("use the set_status command.");
        say("Some components may prompt you for changes to the client as well.");
        say("Syntax:\n");
        say("approve [id | number]\n");
        say("The approval record will be for that client");
        say("\nSee also: set_status");
    }

    public void approve(InputLine inputLine) throws IOException {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }

        ClientApproval ca = (ClientApproval) findItem(inputLine);
        approve(ca);
    }

    public void set_status(InputLine inputLine) throws IOException {
        if (showHelp(inputLine)) {
            say("set_status [id] [new_status] will set the status for the given/current record.");
            say("This is more reliable than simply updating the status property manually.");
            say("If new_status is given, then it will be set to that and the previous status displayed.");
            say("If new_status is missing, you will be prompted. Allowed values for new_status are");
            say("a | approved");
            say("d | denied");
            say("n | none");
            say("p | pending");
            say("r | revoked");
            say("\nand any value not on this list is rejected.");
            return;
        }
        Identifiable item = findItem(inputLine);
        if (item == null) {
            say("sorry, no record found.");
            return;
        }
        ClientApproval approval = (ClientApproval) item;
        String newStatus = null;
        if (inputLine.getArgCount() == 0) {
            newStatus = getInput("enter new status", "a");
        } else {
            newStatus = inputLine.getLastArg();
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
        say("done!");
    }

    /**
     *
     * @param ca
     * @return true if saved.
     * @throws IOException
     */
    public boolean approve(ClientApproval ca) throws IOException {
        boolean isapproved = isOk(getInput("set approved?", ca.isApproved() ? "y" : "n"));
        ca.setApprover(getInput("approver", ca.getApprover()));
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
    public void bootstrap() throws Throwable {
        super.bootstrap();
        getHelpUtil().load("/help/approver_help.xml");
    }
}
