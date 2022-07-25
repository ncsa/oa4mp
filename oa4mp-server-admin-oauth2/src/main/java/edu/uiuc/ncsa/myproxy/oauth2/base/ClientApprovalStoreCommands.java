package edu.uiuc.ncsa.myproxy.oauth2.base;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import java.io.IOException;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/22/13 at  1:51 PM
 */
public class ClientApprovalStoreCommands extends StoreCommands2 {

    public static final String SHOW_UNAPPROVED_FLAG = "-n";

    @Override
    public void extraUpdates(Identifiable identifiable) {
    }

    public ClientApprovalStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public ClientApprovalStoreCommands(MyLoggingFacade logger, Store store) {
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
            case REVOKED:
                statusString = "D";
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
        info("Starting update for client approval id=" + identifiable.getIdentifierString());
        sayi("Enter the information for the client approval");
        clientApproval.setApprover(getInput("name of the approver", clientApproval.getApprover()));
        boolean isapproved = isOk(getInput("set approved?", clientApproval.isApproved() ? "y" : "n"));
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
        say("This will write the correct approval record for a given client. ");
        say("Syntax:\n");
        say("approve [number]\n");
        say("where number refers to the index of the client entry. The approval record will be for that client");
        say("If you do not supply the number, then the list of clients will be displayed and you may choose then");
    }

    public void approve(InputLine inputLine) throws IOException {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }

        ClientApproval ca = (ClientApproval) findItem(inputLine);
        approve(ca);
    }

    public void approve(ClientApproval ca) throws IOException {
        info("Starting approval for id=" + ca.getIdentifierString());
        ca.setApprover(getInput("approver", ca.getApprover()));
        //ca.setApproved(isOk(getInput("approve this", ca.isApproved() ? "y" : "n")));

        boolean isapproved = isOk(getInput("set approved?", ca.isApproved() ? "y" : "n"));
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
            return;
        }
        sayi("approval was not saved.");
        info("Approval cancelled for id=" + ca.getIdentifierString());
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
            sayi("show " + SEARCH_SHORT_REGEX_FLAG +  " qdl.*");
            sayi("shows all approved clients whose identifier starts with qdl");
            sayi("show " + SHOW_UNAPPROVED_FLAG + " "  + SEARCH_SHORT_REGEX_FLAG +" qdl.*");
            sayi("shows all UNapproved clients whose identifier starts with qdl");
        }
        boolean showApproved = !inputLine.hasArg(SHOW_UNAPPROVED_FLAG);
        inputLine.removeSwitch(SHOW_UNAPPROVED_FLAG);
        String regex = null;
        if(inputLine.hasArg(SEARCH_SHORT_REGEX_FLAG)){
            regex = inputLine.getNextArgFor(SEARCH_SHORT_REGEX_FLAG);
            inputLine.removeSwitchAndValue(SEARCH_SHORT_REGEX_FLAG);
        }
        show(showApproved, regex);
    }
}
