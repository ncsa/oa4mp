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
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.util.cli.ExitException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.FileReader;
import java.util.HashMap;
import java.util.List;

import static edu.uiuc.ncsa.security.util.cli.CLIDriver.CLEAR_BUFFER_COMMAND;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.EXIT_COMMAND;

/**
 * Commands for a base client store. This is the super class to several variations of clients.
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  1:03 PM
 */
public abstract class BaseClientStoreCommands extends StoreCommands2 {
    public BaseClientStoreCommands(MyLoggingFacade logger, String defaultIndent, Store clientStore, ClientApprovalStore clientApprovalStore) {
        super(logger, defaultIndent, clientStore);
        this.clientApprovalStore = clientApprovalStore;
        clientApprovalStoreCommands = new ClientApprovalStoreCommands(logger, defaultIndent, clientApprovalStore);
        setSortable(new ClientSorter());
    }

    public BaseClientStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    // used internally to approve records.
    ClientApprovalStoreCommands clientApprovalStoreCommands = null;

    public ClientApprovalStore getClientApprovalStore() {
        return clientApprovalStore;
    }

    public void setClientApprovalStore(ClientApprovalStore clientApprovalStore) {
        this.clientApprovalStore = clientApprovalStore;
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
         sayi("Enter new JSON value. An empty line terminates input. Entering a line with " + EXIT_COMMAND +
                 " will terminate input too.\n Hitting " + CLEAR_BUFFER_COMMAND+ " will clear the contents of this.");
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
        say("would just has \"word\", and to get the whole string you should enter" );
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
        say("creating hash of " + secret);
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
                longFormat((BaseClient) x, tempA);
            } else {
                say((i++) + ". " + format((BaseClient) x, tempA));
            }
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
    protected String format(Identifiable identifiable) {
        BaseClient client = (BaseClient) identifiable;
        ClientApproval ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        return format(client, ca);
    }

    protected void longFormat(BaseClient client, ClientApproval clientApproval) {
        say("Client name=" + (client.getName() == null ? "(no name)" : client.getName()));
        sayi("identifier=" + client.getIdentifier());
        sayi("email=" + client.getEmail());
        sayi("creation timestamp=" + client.getCreationTS());
        sayi("last modified timestamp=" + client.getLastModifiedTS());
        if (clientApproval == null) {
            sayi("no approval record exists.");
        } else {
            if (clientApproval.isApproved()) {
                String approver = "(unknown)";
                if (clientApproval.getApprover() != null) {
                    approver = clientApproval.getApprover();
                }
                sayi("approved by " + approver);
            } else {
                sayi("not approved");
            }
        }

        if (client.getSecret() == null) {
            sayi("secret : (none)");

        } else {
            sayi("secret:");
            say(client.getSecret());
        }

    }


    @Override
    protected void longFormat(Identifiable identifiable) {
        BaseClient client = (BaseClient) identifiable;
        ClientApproval clientApproval = null;
        if (getClientApprovalStore() != null) {
            clientApproval = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        }
        longFormat(client, clientApproval);

    }


    protected void showApproveHelp() {
        clientApprovalStoreCommands.showApproveHelp();
    }

    public void approve(InputLine inputLine) {
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
    public boolean update(Identifiable identifiable) {

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
            sayi2(" remove client with id=\"" + client.getIdentifier() + "\" [y/n]? ");
            removeCurrentClient = isOk(readline());
            client.setIdentifier(BasicIdentifier.newID(newIdentifier));
        }
        sayi2("save [y/n]?");
        if (isOk(readline())) {
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
      if(!getStore().containsKey(x.getIdentifier())){
          sayi("Removing approval record");
          info("Removing approval record for id=" + x.getIdentifierString());
          getClientApprovalStore().remove(x.getIdentifier());
          sayi("Done. Client approval with id = " + x.getIdentifierString() + " has been removed from the store");
          info("Client record removed for id=" + x.getIdentifierString());
      }
    }

/*
    @Override
    public void rm(InputLine inputLine) {

        Identifiable x = findItem(inputLine);
        BaseClient baseClient = (BaseClient)x;
        sayi("Removal of client named \"" + baseClient.getName()+"\"");
        sayi("   with id=\"" + baseClient.getIdentifierString() + "\"");
        String response = getInput("Are you sure you want to remove this client?(y/n)", "n");
        if(!response.equals("y")){
            sayi("aborted...");
            return;
        }

        sayi("Removing approval record");
        info("Removing approval record for id=" + x.getIdentifierString());
        getClientApprovalStore().remove(x.getIdentifier());
        sayi("Done. Client approval with id = " + x.getIdentifierString() + " has been removed from the store");
        info("Client record removed for id=" + x.getIdentifierString());
        super.rm(inputLine);
    }
*/
}
