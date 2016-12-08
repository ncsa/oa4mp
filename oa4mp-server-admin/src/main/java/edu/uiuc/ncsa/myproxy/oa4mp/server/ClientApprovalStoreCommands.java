package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.StoreCommands;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/22/13 at  1:51 PM
 */
public class ClientApprovalStoreCommands extends StoreCommands {
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
    protected void longFormat(Identifiable identifiable) {
        ClientApproval clientApproval = (ClientApproval) identifiable;
        say("\nApprover:" + clientApproval.getApprover());
        say("Identifier:" + clientApproval.getIdentifierString());
        say("Approved at:" + clientApproval.getApprovalTimestamp());
        say("Is approved? " + clientApproval.isApproved());

    }

    @Override
    protected String format(Identifiable identifiable) {
        if (identifiable == null) return "(null)";
        ClientApproval ca = (ClientApproval) identifiable;
        String x = "(" + (ca.isApproved() ? "Y" : "N") + ") " + ca.getIdentifierString();
        if (ca.isApproved()) {
            x = x + " by \"" + ca.getApprover() + "\" on " + ca.getApprovalTimestamp();
        }
        return x;
    }

    @Override
    public String getName() {
        return "  approvals";
    }

    @Override
    public boolean update(Identifiable identifiable) {
        ClientApproval clientApproval = (ClientApproval) identifiable;
        info("Starting update for client approval id=" + identifiable.getIdentifierString());
        sayi("Enter the information for the client approval");
        clientApproval.setApprover(getInput("name of the approver", clientApproval.getApprover()));
        clientApproval.setApproved(isOk(getInput("set approved?", clientApproval.isApproved() ? "y" : "n")));
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

    public void approve(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }

        ClientApproval ca = (ClientApproval) findItem(inputLine);
        approve(ca);
    }

    public void approve(ClientApproval ca) {
        info("Starting approval for id=" + ca.getIdentifierString());
        ca.setApprover(getInput("approver", ca.getApprover()));
        ca.setApproved(isOk(getInput("approve this", ca.isApproved() ? "y" : "n")));
        sayi2("save this approval record [y/n]?");
        if (isOk(readline())) {
            getStore().save(ca);
            sayi("approval saved");
            info("Approval for id = " + ca.getIdentifierString() + " saved");
            return;
        }
        sayi("approval was not saved.");
        info("Approval cancelled for id=" + ca.getIdentifierString());
    }
}
