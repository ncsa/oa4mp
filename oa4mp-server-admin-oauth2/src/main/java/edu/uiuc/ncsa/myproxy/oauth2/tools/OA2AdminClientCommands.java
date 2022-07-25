package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oauth2.base.ClientApprovalStoreCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oauth2.base.BaseClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.util.cli.ArgumentNotFoundException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  12:34 PM
 */
public class OA2AdminClientCommands extends BaseClientStoreCommands {
    public OA2AdminClientCommands(MyLoggingFacade logger,
                                  String defaultIndent,
                                  Store adminClientStore,
                                  ClientApprovalStoreCommands clientApprovalStoreCommands,
                                  PermissionsStore permissionsStore,
                                  ClientStore clientStore) {
        super(logger, defaultIndent, adminClientStore, clientApprovalStoreCommands);
        this.clientStore = clientStore;
        this.permissionsStore = permissionsStore;
    }

    ClientStore clientStore;

    @Override
    public String getName() {
        return "  admins";
    }

    PermissionsStore permissionsStore;

    @Override
    public void print_help(InputLine inputLine) throws Exception {
        super.print_help(inputLine);
        say("--Admin specific commands:");
        sayi("count_clients = How many clients does a given admin manage?");
        sayi("list_admins = who administers a client?");
        sayi("list_clients = list the clients for a specific admin");
    }

    @Override
    public void extraUpdates(Identifiable identifiable) throws IOException {
        AdminClient client = (AdminClient) identifiable;
        String secret = client.getSecret();
        String input;
        boolean askForSecret = true;


        while (askForSecret) {
            input = getInput("enter a new secret (this will be hashed, not stored) or return to skip.", secret);
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
        String issuer = getInput("Give the issuer", client.getIssuer());
        if (!isEmpty(issuer)) {
            client.setIssuer(issuer);
        }
        String voURI;
        if (client.getVirtualOrganization() == null) {
            voURI = getInput("Give the VO", null);
        } else {
            voURI = getInput("Give the VO", client.getVirtualOrganization().toString());
        }

        if (!isEmpty(voURI)) {
            try {
                URI z = URI.create(voURI);
                client.setVirtualOrganization(BasicIdentifier.newID(z));
            } catch (Throwable t) {
                if (DebugUtil.isEnabled()) {
                    t.printStackTrace();
                }
                say("sorry, but that was not a valid identifier");
            }
        }


        String vo;
        if (client.getExternalVOName() == null) {
            vo = getInput("Give the VO", null);
        } else {
            vo = getInput("Give the VO", client.getExternalVOName().toString());
        }

        if (!isEmpty(vo)) {
            client.setExternalVOName(vo);
        }


        String max = getInput("Enter new maximum number of clients allowed", Integer.toString(client.getMaxClients()));
        if (!isEmpty(max)) {
            client.setMaxClients(Integer.parseInt(max));
        }

        JSONObject newConfig = (JSONObject) inputJSON(client.getConfig(), "client configuration");
        if (newConfig != null) {
            client.setConfig(newConfig);
        }

    }

    protected void showListClientsHelp() {
        say("list_clients id|index - list all the clients this administrator manages");
        say("                        This also lists if the client with the given id has been approved.");
    }

    // For CIL-508
    public void list_clients(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showListClientsHelp();
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
        if (adminClient == null) {
            say("Sorry, there is no admin client for this identifier.");
            return;
        }
        List<Identifier> clients = permissionsStore.getClients(adminClient.getIdentifier());
        if (clients == null || clients.isEmpty()) {
            say("(none)");
        }
        for (Identifier identifier : clients) {
            say("(" + (getClientApprovalStore().isApproved(identifier) ? "Y" : "N") + ") " + identifier);
        }
        say(clients.size() + " total clients");
    }

    protected void showCountClientsHelp() {
        say("count_clients id|index - Count the number of clients this administrator manages");
        say("                       For databases, this call is more efficient that getting all the clients and counting them.");
    }


    public void count_clients(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showCountClientsHelp();
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
        if (adminClient == null) {
            say("Sorry, there is no admin client for this identifier.");
            return;
        }
        say("This admin client manages " + permissionsStore.getClientCount(adminClient.getIdentifier()) + " out of a possible " + adminClient.getMaxClients() + ".");
    }


    protected void showListAdminsHelp() {
        say("list_admins id - list the administrators associated with the given client id");
        say("                 Note that you need the actual identifier for the client, not an index.");
    }

    public void list_admins(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showListAdminsHelp();
            return;
        }
        Identifier clientID = null;
        try {
            String rawID = inputLine.getLastArg();
            if (rawID.startsWith("/")) {
                // if they supply a leading / just drop it, since the user is being consistent with other cases.
                rawID = rawID.substring(1);
            }
            clientID = BasicIdentifier.newID(rawID);
        } catch (Throwable t) {
            say("Sorry, \"" + inputLine.getLastArg() + "\" is not a valid identifier. " + t.getMessage());
            return;
        }
        List<Identifier> admins = permissionsStore.getAdmins(clientID);
        if (admins == null || admins.isEmpty()) {
            say("(none)");
            return;
        }
        for (Identifier id : admins) {
            AdminClient adminClient = (AdminClient) getStore().get(id);
            say(format(adminClient, (ClientApproval) getClientApprovalStore().get(adminClient.getIdentifier())));
        }
        say(admins.size() + " admin clients");

    }

    @Override
    protected void showDeserializeHelp() {
        super.showDeserializeHelp();
        say("NOTE that for clients, the assumption is that you are supplying the hashed secret, not the actual secret.");
        say("If you need to create a hash of a secret, invoke the create_hash method on the secret");
    }

    public static String LINK_NEW_CLIENT_FLAG = "-new";
    public static String LINK_RANDOM_CLIENT_ID_ARG = "?";

    public void link(InputLine inputLine) {
        if (showHelp(inputLine)) {
            say("link client_id [admin_id]- link the client with the given client_id admin client");
            say("link " + LINK_NEW_CLIENT_FLAG + " " + LINK_RANDOM_CLIENT_ID_ARG + " | client_id [admin_id]- create a new client and link it with the given client_id admin client");
            say("   You must supply either a new client id or a \"" + LINK_RANDOM_CLIENT_ID_ARG + "\". If a " + LINK_RANDOM_CLIENT_ID_ARG
                    + " is used, then a random identifier will be created.");
            say("Note that if you do not pas in an admin_id, the current one is used.");
            say("See also: unlink");
            return;
        }
        boolean createNewClient = inputLine.hasArg(LINK_NEW_CLIENT_FLAG);
        Identifier client_id = null;

        if (createNewClient) {
            String newID = inputLine.getNextArgFor(LINK_NEW_CLIENT_FLAG);
            OA2Client client = (OA2Client) clientStore.create();
            if (newID.equals(LINK_RANDOM_CLIENT_ID_ARG)) {
                client_id = client.getIdentifier();
            } else {
                client_id = BasicIdentifier.newID(newID);
                if (clientStore.containsKey(client_id)) {
                    say("sorry but the client with id \"" + client_id + "\" already exists. aborting.");
                    return;
                }
                client.setIdentifier(client_id);
            }
            clientStore.save(client);// done creating a new client if need be
            say("new client with id \"" + client.getIdentifierString() + "\" created. You must edit this separately.");
            inputLine.removeSwitchAndValue(LINK_NEW_CLIENT_FLAG);
        } else {
            try {
                client_id = BasicIdentifier.newID(inputLine.getArg(1)); // arg 0 is the name of the command.
            } catch (ArgumentNotFoundException argumentNotFoundException) {
                say("sorry. No id supplied. You must specify the new id you want or use a " + LINK_RANDOM_CLIENT_ID_ARG + " to create a random one");
                return;
            }
            inputLine.removeArgAt(1);
        }
        // arguments have been whittled down to the point we can get the admin client.

        AdminClient adminClient = (AdminClient) findItem(inputLine);

        // check if the client already exists.
        PermissionList permissionList = permissionsStore.get(adminClient.getIdentifier(), client_id);
        if (permissionList != null && !permissionList.isEmpty()) {
            say("sorry, this client is already managed by this admin.");
            return;
        }

        Permission permission = (Permission) permissionsStore.create();
        // The permissions are what the admin client can do to the OA2 client.
        permission.setApprove(true);
        permission.setCreate(true);
        permission.setDelete(true);
        permission.setRead(true);
        permission.setWrite(true);
        permission.setClientID(client_id);
        permission.setAdminID(adminClient.getIdentifier());
        permissionsStore.save(permission);
        say("done. The client with identifier \"" + client_id + "\" is now managed by \"" + adminClient.getIdentifierString() + "\"");
    }

    public static final String UNLINK_ALL_FLAG = "-all";
    public static final String UNLINK_REMOVE_FLAG = "-rm";

    protected void unlinkRS(InputLine inputLine) {
        String rsName = inputLine.getNextArgFor(SEARCH_RESULT_SET_NAME);
        RSRecord rsRecord = null;
        if (isCARS(rsName)) {
            rsRecord = clientApprovalStoreCommands.getResultSets().get(rsName);
        } else {
            rsRecord = getResultSets().get(rsName);
        }
        if (rsRecord == null) {
            say("sorry, result set \"" + rsName + "\" not found");
            return;
        }

    }

    public void unlink(InputLine inputLine) {
        if (showHelp(inputLine)) {
            say("unlink " + UNLINK_ALL_FLAG + " | client_id  + [" + UNLINK_REMOVE_FLAG + "] [admin_id]- unlink the client with the given client_id admin client");
            say(UNLINK_ALL_FLAG + " - (no client_id) unlink all clients, not just the specified one.");
            say(UNLINK_REMOVE_FLAG + " - remove clients that are unlinked.");
            say("This means that the clients will still exist unless you specifially remove them.");
            say("Properly speaking, you would use the " + UNLINK_ALL_FLAG + " only before removing the ");
            say("admin client itself and retiring it.");
            say("See also: link");
            return;
        }
        if (inputLine.hasArg(SEARCH_RESULT_SET_NAME)) {
            unlinkRS(inputLine);
            return;
        }
        boolean removeClient = inputLine.hasArg(UNLINK_REMOVE_FLAG);
        inputLine.removeSwitch(UNLINK_REMOVE_FLAG);

        boolean doAll = inputLine.hasArg(UNLINK_ALL_FLAG);
        inputLine.removeSwitch(UNLINK_ALL_FLAG);

        if (doAll && hasId() && 0 < inputLine.getArgCount()) {
            say("Sorry, but you have specified a client id and the " + UNLINK_ALL_FLAG + " flag. aborted.");
            return;
        }
        Identifier clientID = null; // arg 0 is name of command
        if (!doAll) {
            clientID = BasicIdentifier.newID(inputLine.getArg(1)); // arg 0 is name of command
            inputLine.removeArgAt(1);
        }


        AdminClient adminClient = (AdminClient) findItem(inputLine);

        OA2Client client = null;
        // check if the client already exists.
        List<Identifier> clients;
        int count = 0;
        int pcount = 0; // count the permissions processed too.

        if (doAll) {
            clients = permissionsStore.getClients(adminClient.getIdentifier());
        } else {
            clients = new ArrayList<>();
            clients.add(clientID);
        }

        for (Identifier clientIdentifier : clients) {
            count++;
            sayv("removing permissions for " + clientIdentifier);
            PermissionList permissionList = permissionsStore.get(adminClient.getIdentifier(), clientIdentifier);
            for (Permission permission : permissionList) {
                pcount++;
                permissionsStore.remove(permission.getIdentifier());
                if (removeClient) {
                    sayv("removing client and approval: " + permission.getClientID());
                    clientStore.remove(permission.getClientID());
                    getClientApprovalStore().remove(permission.getClientID());
                }
            }
        }
        say("done. Removed " + count + " clients and processed " + pcount + " permissions");
    }


    public void list_ersatz(InputLine inputLine)throws Exception{
        if (showHelp(inputLine)) {
            say("list_ersatz client_id [admin_id] = list all of the clients granted substitute privilege.");
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
         if (adminClient == null) {
             say("Sorry, there is no admin client for this identifier.");
             return;
         }
         Identifier clientID = BasicIdentifier.newID(inputLine.getArg(1));

        PermissionList ersatzClients = permissionsStore.getErsatzChains(adminClient.getIdentifier(), clientID);

         if (ersatzClients == null || ersatzClients.isEmpty()) {
             say("(none)");
             return;
         }
         int count = 0;
         for (Permission p : ersatzClients) {
             say(p.getErsatzChain().toString());
         }
         say(count + " total ersatz clients for " + clientID);
    }
    public void set_ersatz(InputLine inputLine) throws Exception{
        if(showHelp(inputLine)){
            say("set_ersatz client_id ersatz_id [admin_id] = simple case, that sets permission for a single ersatz_id  for client_id");
            say("in token exchanges. Onus is on the user of the CLI not to set something goofy.");
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
        if(inputLine.getArgCount() < 3){
            say("missing argument. You need both a client id and its ersatz id");
            return;
        }
        Identifier ersatzID = BasicIdentifier.newID(inputLine.getArg(1));
        Identifier clientID = BasicIdentifier.newID(inputLine.getArg(2));
        Permission permission = (Permission) permissionsStore.create();
        permission.setAdminID(adminClient.getIdentifier());
        permission.setClientID(clientID);
        JSONArray array = new JSONArray();
        array.add(ersatzID);
        permission.setErsatzChain(array);
        permission.setSubstitute(true);
        permissionsStore.save(permission);
        say("done");
    }
    /*
    adminID = admin:test/vo_1
    client_id = localhost:command.line2
    ersatz_id = client:/my_ersatz
     */
}
