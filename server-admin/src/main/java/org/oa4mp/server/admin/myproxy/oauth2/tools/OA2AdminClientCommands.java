package org.oa4mp.server.admin.myproxy.oauth2.tools;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientKeys;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionList;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.server.admin.myproxy.oauth2.base.BaseClientStoreCommands;
import org.oa4mp.server.admin.myproxy.oauth2.base.ClientApprovalStoreCommands;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.ArgumentNotFoundException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

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
                                  ClientStore clientStore) throws Throwable {
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
    public void print_help() throws Exception {
        super.print_help();
        say("--Admin specific commands:");
        sayi("count_clients = How many clients does a given admin manage?");
        sayi("list_admins = who administers a client?");
        sayi("list_clients = list the clients for a specific admin");
    }

    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {
        AdminClient client = (AdminClient) identifiable;
        AdminClientKeys keys = (AdminClientKeys) getSerializationKeys();
        super.extraUpdates(client, magicNumber);
        String issuer = getPropertyHelp(keys.issuer(), "Give the issuer", client.getIssuer());
        if (!isEmpty(issuer)) {
            client.setIssuer(issuer);
        }
        String viURI;
        if (client.getVirtualIssuer() == null) {
            viURI = getPropertyHelp(keys.voURI(), "Give the VI URI", null);
        } else {
            viURI = getPropertyHelp(keys.voURI(), "Give the VI URI", client.getVirtualIssuer().toString());
        }
        if (!isEmpty(viURI)) {
            try {
                URI z = URI.create(viURI);
                client.setVirtualIssuer(BasicIdentifier.newID(z));
            } catch (Throwable t) {
                if (DebugUtil.isEnabled()) {
                    t.printStackTrace();
                }
                say("sorry, but that was not a valid identifier");
            }
        }


        String vi;
        if (client.getExternalVIName() == null) {
            String vvv = client.getVirtualIssuer().toString();
            vi = getPropertyHelp(keys.vo(), "Give the VI", vvv); // offer the other VO (real one) as default
        } else {
            vi = getPropertyHelp(keys.vo(), "Give the VI", client.getExternalVIName().toString());
        }

        if (!isEmpty(vi)) {
            client.setExternalVIName(vi);
        }
        client.setAllowQDL(getPropertyHelp(keys.allowQDL(), "allow QDL?", "n").equalsIgnoreCase("y"));
        if (client.isAllowQDL()) {
            client.setAllowQDLCodeBlocks(getPropertyHelp(keys.allowQDLCodeBlocks(), "  allow code blocks containing QDL (y/n)?", "n").equalsIgnoreCase("y"));
        }


        if (getInput("configure advanced options (y/n)?", "n").equalsIgnoreCase("y")) {
            JSONObject newConfig = (JSONObject) inputJSON(client.getConfig(), "client configuration");
            String max = getPropertyHelp(keys.maxClients(), "Enter new maximum number of clients allowed", Integer.toString(client.getMaxClients()));
            if (!isEmpty(max)) {
                client.setMaxClients(Integer.parseInt(max));
            }
            if (newConfig != null) {
                client.setConfig(newConfig);
            }
            if (getPropertyHelp(keys.allowCustomIDs(), "allow custom ids in client management (y/n)?", "n").equalsIgnoreCase("y")) {
                client.setAllowCustomIDs(true);
                if (getPropertyHelp(keys.generateIDs(), "  generate ids automatically (y/n)?", "y").equalsIgnoreCase("y")) {
                    client.setGenerateIDs(true);
                } else {
                    client.setGenerateIDs(false);
                    client.setUseTimestampInIDs(getPropertyHelp(keys.useTimestampsInIds(), "  use timestamps in IDs (y/n)?", "y").equalsIgnoreCase("y"));
                    String head = getPropertyHelp(keys.idHead(), "  uri to use as start of custom ids (return only for system default)", "");
                    if (!isEmpty(head)) {
                        client.setIdHead(URI.create(head));
                    }
                }
            }
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
        TreeSet<Identifier> sortedClients = new TreeSet<>();
        sortedClients.addAll(clients);
        for (Identifier identifier : sortedClients) {
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
            if (adminClient != null) { // if there are dead ids in the store, don't bomb with an NPE.
                say(format(adminClient, (ClientApproval) getClientApprovalStore().get(adminClient.getIdentifier())));
            }
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

    public static String NO_VERIFY_ALL_FLAG = "-no_verify";

    public void unlink(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("unlink " + UNLINK_ALL_FLAG + " | client_id  + [" + UNLINK_REMOVE_FLAG + "]  + [" + NO_VERIFY_ALL_FLAG + "] [admin_id]- unlink the client with the given client_id admin client");
            say(UNLINK_ALL_FLAG + " - (no client_id) unlink all clients, not just the specified one.");
            say(UNLINK_REMOVE_FLAG + " - remove clients that are unlinked.");
            say(NO_VERIFY_ALL_FLAG + "- if present will suppress asking if you really meant to use the ");
            say("This means that the clients will still exist unless you specifially remove them.");
            say("Properly speaking, you would use the " + UNLINK_ALL_FLAG + " only before removing the " + UNLINK_ALL_FLAG + " switch.");
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

        boolean noVerifyAll = inputLine.hasArg(NO_VERIFY_ALL_FLAG);
        inputLine.removeSwitch(NO_VERIFY_ALL_FLAG);

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
        if (adminClient == null) {
            say("sorry, admin client with id \"" + clientID + "\" not found");
            return;
        }
        OA2Client client = null;
        // check if the client already exists.
        List<Identifier> clients;
        int count = 0;
        int pcount = 0; // count the permissions processed too.

        if (doAll) {
            clients = permissionsStore.getClients(adminClient.getIdentifier());
            // Fix https://github.com/ncsa/oa4mp/issues/116
            if(clients.size() == 0){
                say("no clients found");
                return ;
            }
            if (!noVerifyAll) {
                if (!readline("unlink ALL " + clients.size() + " of the clients for admin \"" + adminClient.getIdentifierString() + "\"?(Y/n)").equals("Y")) {
                    say("aborting...");
                    return;
                }
            }
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

    public void list_provisioners(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("list_provisioners ersatz_id [admin_id] = list all of the clients that are provisioners for this ersatz client.");
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
        if (adminClient == null) {
            say("Sorry, there is no admin client for this identifier.");
            return;
        }
        if (inputLine.getArgCount() == 0) {
            say("you must supply the ersatz client id");
            return;
        }
        Identifier ersatzID = BasicIdentifier.newID(inputLine.getArg(1));

        PermissionList provisioners = permissionsStore.getProvisioners(adminClient.getIdentifier(), ersatzID);

        if (provisioners == null || provisioners.isEmpty()) {
            say("(none)");
            return;
        }
        int count = 0;
        for (Permission p : provisioners) {
            count++;
            say(p.getClientID().toString());
        }
        say(count + " total provisioners for " + ersatzID);

    }

    public void list_ersatz(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("list_ersatz client_id [admin_id] = list all of the clients granted substitute privilege.");
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
        if (adminClient == null) {
            say("Sorry, there is no admin client for this identifier.");
            return;
        }
        if (inputLine.getArgCount() == 0) {
            say("you must supply the client id");
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
            count++;
            if (p.getErsatzChain().size() == 1) {
                say(p.getErsatzChain().get(0).toString()); // the unique element is a singleton
            } else {
                say(p.getErsatzChain().toString()); // whole thing if multiples
            }
        }
        say(count + " total ersatz clients for " + clientID);
    }

    public void set_ersatz(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("set_ersatz client_id ersatz_id [admin_id] = simple case, that sets permission for a single ersatz_id  for client_id");
            say("in token exchanges. Onus is on the user of the CLI not to set something goofy.");
            return;
        }
        AdminClient adminClient = (AdminClient) findItem(inputLine);
        if (inputLine.getArgCount() < 2) {
            say("missing argument. You need both a client id and its ersatz id");
            return;
        }
        Identifier clientID = BasicIdentifier.newID(inputLine.getArg(1));
        Identifier ersatzID = BasicIdentifier.newID(inputLine.getArg(2));
        Permission permission = (Permission) permissionsStore.create();
        permission.setAdminID(adminClient.getIdentifier());
        permission.setClientID(clientID);
        List<Identifier> eChain = new ArrayList<>();
        eChain.add(ersatzID);
        permission.setErsatzChain(eChain);
        permission.setSubstitute(true);
        permissionsStore.save(permission);
        say("done");
    }
    /*
    adminID = admin:test/vo_1
    client_id = localhost:command.line2
    ersatz_id = client:/my_ersatz
     */

    @Override
    public void bootstrap() throws Throwable {
        super.bootstrap();
        getHelpUtil().load("/help/admin_help.xml");
    }

    @Override
    protected BaseClient approvalMods(InputLine inputLine, BaseClient client) throws IOException {
        // Fix https://github.com/ncsa/oa4mp/issues/109
        AdminClient adminClient = (AdminClient) client;
        adminClient.setAllowQDL("y".equals(getInput("Allow QDL in scripts?(y/n)", adminClient.isAllowQDL() ? "y" : "n")));
        return adminClient;
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        int updateCount = 0;
        List<Permission> permissions = getEnvironment().getPermissionStore().getByAdminID(oldID);
        if(!copy){
            // Do not just copy the permissions with the new ID, remove the old ones.
            getEnvironment().getPermissionStore().remove(permissions);
        }
        for (Permission p : permissions) {
            p.setAdminID(newID);
            getEnvironment().getPermissionStore().save(p);
        }
        return permissions.size();
    }
}
