package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;

import java.io.File;
import java.util.LinkedList;
import java.util.Set;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/16/13 at  3:23 PM
 */
public class ClientStoreUtil extends ServerCLI {
    @Override
    public void create() throws Exception {
        boolean tryAgain = true;
        Identifier id = null;
        Client c = null;
        while (tryAgain) {
            say2("enter the id of the object you want to create or return for a random one");
            String inLine = readline();

            if (!(inLine == null || inLine.length() == 0)) {
                try {
                    id = BasicIdentifier.newID(inLine);
                } catch (Throwable t) {
                    say2("That is not a valid uri. Try again (y/n)?");
                    inLine = readline().trim().toLowerCase();
                    tryAgain = inLine.equals("y");
                }
            }else{
                tryAgain = false;
            }
        } // end input loop.
        c = (Client) getSE().getClientStore().create();
        if (id == null) {
            // use random one
        } else {
            if (getSE().getClientStore().containsKey(id)) {
                // something should happen since this exists.
            }
            c.setIdentifier(id);
        }
        // now invoke updater on the new item.
        update(c);
        getSE().getClientStore().save(c);
    }

    protected void update(Client c) throws Exception {
        say("Enter the information. A return accepts the current value.");
        say("identifier[" + c.getIdentifier() + "]:");
    }

    ServiceEnvironmentImpl getSE() throws Exception {
        return (ServiceEnvironmentImpl) getEnvironment();
    }

    @Override
    protected Store getStore() throws Exception {
        return getSE().getClientStore();
    }

    @Override
    public void update() throws Exception {
        say("implement me...");
    }

    @Override
    protected LinkedList<Identifiable> listAll() throws Exception {
        say("select the number of the item below:");
        ClientApprovalStore cas = getSE().getClientApprovalStore();
        Set keys = getStore().keySet();
        LinkedList<Identifiable> linkedList = new LinkedList<Identifiable>();
        int i = 0;
        for (Object key : keys) {
            boolean isApproved = false;
            ClientApproval ca = (ClientApproval) cas.get(key);
            if (ca != null) {
                isApproved = ca.isApproved();
            }
            Identifiable x = (Identifiable) getStore().get(key);
            linkedList.add(x);
            say((i++) + "." + "(" + (isApproved ? "A" : "D") + ") " + x.getIdentifierString());
        }

        if (linkedList.isEmpty()) {
            say("(no entries found)");
        }
        return linkedList;
    }


    public static void main(String[] args) {
        ClientStoreUtil csu = new ClientStoreUtil();
        try {
            System.out.println("logging to file " + new File(csu.getLogfileName()).getAbsolutePath());
            csu.run(args);
        } catch (Throwable e) {
            // Since this will probably be called only by a bash script, catch all errors and exceptions
            // then return a non-zero exit code
            e.printStackTrace();
            // System.exit(1);
        }
    }
}
