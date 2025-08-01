package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.ObjectNotFoundException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.server.admin.oauth2.base.BaseClientStoreCommands;
import org.oa4mp.server.admin.oauth2.base.ClientApprovalStoreCommands;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientKeys;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionKeys;
import org.oa4mp.server.api.admin.permissions.PermissionList;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2ClientKeys;

import java.io.IOException;
import java.net.URI;
import java.util.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  12:34 PM
 */
public class OA2AdminClientCommands extends BaseClientStoreCommands {
    public OA2AdminClientCommands(CLIDriver driver,
                                  String defaultIndent,
                                  Store adminClientStore,
                                  ClientApprovalStoreCommands clientApprovalStoreCommands,
                                  PermissionsStore permissionsStore,
                                  ClientStore clientStore) throws Throwable {
        super(driver, defaultIndent, adminClientStore, clientApprovalStoreCommands);
        this.clientStore = clientStore;
        this.permissionsStore = permissionsStore;
    }
@Override
        public void initialize() throws Throwable{

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
        say("list_clients index - list all the clients this administrator manages");
        say("                        This also lists if the client with the given id has been approved.");
        printIndexHelp(true);
    }

    // For CIL-508
    public void list_clients(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showListClientsHelp();
            return;
        }
        AdminClient adminClient = (AdminClient) findSingleton(inputLine, "admin client not found");
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
        say("count_clients index - Count the number of clients this administrator manages");
        say("                       For databases, this call is more efficient that getting all the clients and counting them.");
        printIndexHelp(false);
    }


    public void count_clients(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showCountClientsHelp();
            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("Sorry, there is no admin client for this identifier.");
            return;
        }
        for (Identifiable identifiable : identifiables) {
            AdminClient adminClient = (AdminClient) identifiable;
            say("admin client " + adminClient.getIdentifierString() + " manages " + permissionsStore.getClientCount(adminClient.getIdentifier()) + " out of a possible " + adminClient.getMaxClients() + ".");
        }

    }


    protected void showListAdminsHelp() {
        say("list_admins client_id - list the administrators associated with the given client id");
        say("                 You may specify an result set of clients (not admin clients).");
        say("E.g.");
        say("admins>list_admins - [1,3,4,5] my_clients");
        say("would list the admin clients for entries 1, 3, 4 and 5 in the result set my_clients");
        printIndexHelp(false);
    }

    public void list_admins(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showListAdminsHelp();
            return;
        }
        if (inputLine.getArgCount() == 0) {
            say("no clients identifier found");
            return;
        }
        Identifier clientID = BasicIdentifier.newID(inputLine.getLastArg());
        FoundIdentifiables foundClients = findItem(getEnvironment().getClientStore(), inputLine, true);
        //BaseClient baseClient = (BaseClient) getEnvironment().getClientStore().get(clientID);
        if (foundClients == null) {
            say("client not found.");
            return;
        }
        for (Identifiable identifiable : foundClients) {
            BaseClient baseClient = (BaseClient) identifiable;
            List<Identifier> admins = permissionsStore.getAdmins(baseClient.getIdentifier());
            say(admins.size() + " admins for " + baseClient.getIdentifierString());
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
            if (1 < foundClients.size()) {
                say(StringUtils.hLine("-", 40));
            }
        }
    }

    @Override
    protected void showDeserializeHelp() {
        super.showDeserializeHelp();
        say("NOTE that for clients, the assumption is that you are supplying the hashed secret, not the actual secret.");
        say("If you need to create a hash of a secret, invoke the create_hash method on the secret");
    }

    public static String LINK_NEW_CLIENT_FLAG = "-new";
    public static String LINK_RANDOM_CLIENT_ID_ARG = "?";

    public void link(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("link client_id index - link the client with the given client_id to the admin client");
            say("link " + LINK_NEW_CLIENT_FLAG + " (" + LINK_RANDOM_CLIENT_ID_ARG + " | client_id) index- " +
                    "create a new client and link it with the given client_id admin client");
            say("   You must supply either a new client id or a \"" + LINK_RANDOM_CLIENT_ID_ARG + "\". If a " + LINK_RANDOM_CLIENT_ID_ARG
                    + " is used, then a random identifier will be created. This merely creates it, you must edit it later.");
            printIndexHelp(true);
            say("See also: unlink");
            return;
        }
        boolean createNewClient = inputLine.hasArg(LINK_NEW_CLIENT_FLAG);
        Identifier clientID = null;
        List<Identifiable> clients;
        boolean isRS = false;
        List<Identifier> clientIDs;
        if (createNewClient) {
            String newID = inputLine.getNextArgFor(LINK_NEW_CLIENT_FLAG);
            OA2Client client = (OA2Client) clientStore.create();
            if (newID.equals(LINK_RANDOM_CLIENT_ID_ARG)) {
                clientID = client.getIdentifier();
            } else {
                clientID = BasicIdentifier.newID(newID);
                if (clientStore.containsKey(clientID)) {
                    say("sorry but the client with id \"" + clientID + "\" already exists. aborting.");
                    return;
                }
                client.setIdentifier(clientID);
            }
            clientStore.save(client);// done creating a new client if need be
            say("new client with id \"" + client.getIdentifierString() + "\" created. You must edit this separately.");
            inputLine.removeSwitchAndValue(LINK_NEW_CLIENT_FLAG);
            clientIDs = new ArrayList<>(1);
            clientIDs.add(clientID);
        } else {
            String rawID = inputLine.getArg(1);
            clients = findByIDOrRS(getEnvironment().getClientStore(), rawID);
            if (clients == null) {
                say("sorry. could not find a client or ID");
                return;
            }
            isRS = true;
            clientIDs = new ArrayList<>(clients.size());
            for (Identifiable client : clients) {
                clientIDs.add(client.getIdentifier());
            }
        }
        // arguments have been whittled down to the point we can get the admin client.
        AdminClient adminClient = (AdminClient) findSingleton(inputLine, "admin client not found");
        int pass = 0;
        int fail = 0;

        // check if the client already exists.
        for (Identifier client_id : clientIDs) {
            PermissionList permissionList = permissionsStore.get(adminClient.getIdentifier(), client_id);
            if (permissionList != null && !permissionList.isEmpty()) {
                say("sorry, client \"" + client_id + "\" is already managed by this admin.");
                fail++;
                continue;
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
            pass++;
        }
        if (isRS) {
            say("done. " + pass + " clients are " + "now managed by \"" + adminClient.getIdentifierString() + "\"");
            if (0 < fail) {
                say(fail + " clients were already managed.");
            }
            return;
        }
        say("done. The client with identifier \"" + clientID + "\" is now managed by \"" + adminClient.getIdentifierString() + "\"");
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

    public void unlink(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("unlink " + UNLINK_ALL_FLAG + " | (client_id | rs)  + [" + UNLINK_REMOVE_FLAG + "]  + [" + NO_VERIFY_ALL_FLAG + "] index- unlink the client with the given client_id admin client");
            say(UNLINK_ALL_FLAG + " - (client_id ignored!) unlink all clients, not just the specified one.");
            say(UNLINK_REMOVE_FLAG + " - remove clients that are unlinked.");
            say("This means that the clients will still exist unless you specifially remove them.");
            say(NO_VERIFY_ALL_FLAG + "- if present will suppress asking if you really meant to use the " + UNLINK_REMOVE_FLAG + " flag.");
            say("Scenarios are");
            say("1. Removing an admin and all its clients. Run this with the " + UNLINK_ALL_FLAG + ", " + UNLINK_REMOVE_FLAG + " and " + NO_VERIFY_ALL_FLAG);
            say("   flags, then remove the admin itself.");
            say("2. Removing and admin, but keeping its clients (e.g., to move them to another admin in another virtual issuer.");
            say("   Run this with the " + UNLINK_ALL_FLAG + " and remove the admin. The clients are still there.");
            printIndexHelp(false);
            say("See also: link");
            return;
        }
/*        if (inputLine.hasArg(SEARCH_RESULT_SET_NAME)) {
            unlinkRS(inputLine);
            return;
        }*/
        boolean doAll = inputLine.hasArg(UNLINK_ALL_FLAG);
        boolean removeClient = inputLine.hasArg(UNLINK_REMOVE_FLAG);
        inputLine.removeSwitch(UNLINK_REMOVE_FLAG);

        boolean noVerifyAll = inputLine.hasArg(NO_VERIFY_ALL_FLAG);
        inputLine.removeSwitch(NO_VERIFY_ALL_FLAG);
        List<Identifier> client_ids;
        AdminClient adminClient = (AdminClient) findSingleton(inputLine, "admin client not found");

        if (doAll) {
            inputLine.removeSwitch(UNLINK_ALL_FLAG);
            client_ids = permissionsStore.getClients(adminClient.getIdentifier());
            // Fix https://github.com/ncsa/oa4mp/issues/116
            if (client_ids.size() == 0) {
                say("no clients found");
                return;
            }
            if (!noVerifyAll) {
                if (!readline("unlink ALL " + client_ids.size() + " of the clients for admin \"" + adminClient.getIdentifierString() + "\"?(Y/n)").equals("Y")) {
                    say("aborting...");
                    return;
                }
            }
        } else {
            String rawID = inputLine.getArg(1);
            inputLine.removeArgAt(1);
            List<Identifiable> ids = findByIDOrRS(getEnvironment().getClientStore(), rawID);
            if (ids == null) {
                say("no clients found. aborting");
                return;
            }
            client_ids = new ArrayList<>(ids.size());
            // we need the identifiers
            for (Identifiable id : ids) {
                client_ids.add(id.getIdentifier());
            }
        }

        int count = 0;
        int pcount = 0; // count the permissions processed too.


        for (Identifier clientIdentifier : client_ids) {
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

    public void list_provisioners(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("list_provisioners [" + RESULT_SET_KEY + " rs_name] ersatz_id  = list all of the clients that are provisioners for this ersatz client.");
            say("If you specify a result set, the result will be a set of clients. to view it, sue the clients component, e.g.");
            say("// clients rs show rs_name");
            printIndexHelp(true);
            return;
        }
        if (inputLine.getArgCount() == 0) {
            say("you must supply the ersatz client id");
            return;
        }
        boolean useResultSet = inputLine.hasArg(RESULT_SET_KEY);
        String rsName = null;
        RSRecord rsRecord = null;
        List<Identifiable> provisionerList = null;
        if (useResultSet) {
            rsName = inputLine.getNextArgFor(RESULT_SET_KEY);
            inputLine.removeSwitchAndValue(RESULT_SET_KEY);
            provisionerList = new ArrayList<>();
        }
        PermissionKeys permissionKeys = new PermissionKeys();
        Identifier ersatzID = BasicIdentifier.newID(inputLine.getLastArg());

        // Use java escaping because the ersatz id is a JSON blob. THis might timeout for really huge lists of
        // ersatz id's....
        List<Permission> provisioners = getEnvironment().getPermissionStore().search(permissionKeys.ersatzID(), ".*\\Q" + ersatzID + "\\E.*", true);

        if (provisioners == null || provisioners.isEmpty()) {
            say("(none)");
            return;
        }

        if (useResultSet) {
            provisionerList = new ArrayList<>(provisioners.size());
        }

        int count = 0;
        for (Permission p : provisioners) {
            if (p.getErsatzChain().contains(ersatzID)) {
                // since we have to muck about with JSON internally, make sure this is not a false positive
            //    AdminClient x = (AdminClient) getStore().get(p.getAdminID());
                OA2Client pClient = (OA2Client) getEnvironment().getClientStore().get(p.getClientID());
                if (pClient != null) { // possible this is stale reference. Don't add it
                    count++;
                    say(pClient.getIdentifierString());
                    if (useResultSet) {
                        provisionerList.add(pClient);
                    }
                }
            }

        }
        if (count == 0) {
            say("no clients found");
            return;
        }
        if (useResultSet) {
            rsRecord = new RSRecord(provisionerList, (new OA2ClientKeys()).allKeys());
            getResultSets().put(rsName, rsRecord);
        }
        say(count + " total provisioners for " + ersatzID);

    }

    public void list_ersatz(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("list_ersatz [client_id] [" + RESULT_SET_KEY + " rs_name] + admin_id = list all of the clients granted substitute privilege.");
            say("No client id lists all of the ersatz clients known to the admin");
            say("Result sets without a client id will contain every such client. To view the result set, use the clients component:");
            say("// clients rs show rs_name");
            printIndexHelp(true);
            return;
        }
        boolean hasRS = inputLine.hasArg(RESULT_SET_KEY);
        String rsName = null;
        RSRecord rsRecord = null;
        HashSet<Identifier> rsErsatzIDs = null;
        List<Identifiable> allErsatz = new LinkedList<>();
        if (hasRS) {
            rsName = inputLine.getNextArgFor(RESULT_SET_KEY);
            inputLine.removeSwitchAndValue(RESULT_SET_KEY);
            rsRecord = new RSRecord();
            rsErsatzIDs = new HashSet<>();
            allErsatz = new LinkedList<>();
        }
        AdminClient adminClient;
        try {
             adminClient = (AdminClient) findSingleton(inputLine, "admin client not found");
        }catch( ObjectNotFoundException e){
            say(e.getMessage());
            return;
        }
        if (inputLine.getArgCount() == 0) {
            PermissionKeys permissionKeys = new PermissionKeys();
            List<Permission> provisioners = getEnvironment().getPermissionStore().search(permissionKeys.adminID(), adminClient.getIdentifierString(), false);
            HashSet<Identifier> ersatzIds = null;
            HashMap<Identifier, HashSet<Identifier>> idsByProvisioner = new HashMap<>();
            for (Permission p : provisioners) {
                if (p.getErsatzChain() != null && !p.getErsatzChain().isEmpty()) {
                    if (idsByProvisioner.containsKey(p.getClientID())) {
                        ersatzIds = idsByProvisioner.get(p.getClientID());
                    } else {
                        ersatzIds = new HashSet<>();
                        idsByProvisioner.put(p.getClientID(), ersatzIds);
                    }
                    ersatzIds.addAll(p.getErsatzChain());

                }
            }
            if (idsByProvisioner.size() == 0) {
                say("no ersatz clients found");
                return;
            }
            // so now we have every one of these by provisioner id. Start printing...
            int width = 0;
            for (Identifier id : idsByProvisioner.keySet()) {
                width = Math.max(width, id.toString().length());
            }
            width = width + 2;
            int count = 0;
            boolean printHeader = true;
            String hLine = StringUtils.repeatString("-" , width) + " + " + StringUtils.repeatString("-", width);

            for (Identifier id : idsByProvisioner.keySet()) {
                ersatzIds = idsByProvisioner.get(id);
                boolean firstPass = true;
                if (!ersatzIds.isEmpty()) {
                    for (Identifier eID : ersatzIds) {
                        Identifiable x = (Identifiable) getEnvironment().getClientStore().get(eID);
                        if(x != null){
                            count++;
                            if(hasRS){
                                if(!rsErsatzIDs.contains(eID)){
                                    rsErsatzIDs.add(eID);
                                    allErsatz.add(x);
                                }
                            }
                            if (firstPass) {
                                if(printHeader) {
                                    say(StringUtils.center("client id", width) + " | " + StringUtils.center("ersatz client id", width));
                                    printHeader = false;
                                }
                                say(hLine);
                                say(StringUtils.RJustify(id.toString(), width) + " | " + eID);
                                firstPass = false;
                            } else {
                                say(StringUtils.getBlanks(width) + " | " + eID);
                            }

                        }
                    }
                }
            }
            if(count == 0){
                say("no ersatz clients found");
                return;
            }
            if(hasRS){
                if(!rsErsatzIDs.isEmpty()){
                    OA2ClientKeys keys = new OA2ClientKeys();
                    rsRecord = new RSRecord(allErsatz, keys.allKeys());
                    getResultSets().put(rsName, rsRecord);
                }
            }
            say(count + " total ersatz clients");
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

    public void set_ersatz(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_ersatz client_id ersatz_id index = simple case, that sets permission for a single ersatz_id  for client_id");
            say("in token exchanges. Onus is on the user of the CLI not to set something goofy.");
            printIndexHelp(true);
            return;
        }
        AdminClient adminClient = (AdminClient) findSingleton(inputLine, "admin client not found");
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
    protected void initHelp() throws Throwable {
        super.initHelp();
        getHelpUtil().load("/help/admin_help.xml");
    }

    public static final String APPROVAL_QDL_ENABLE = "-qdl";

    public static class AdminApprovalModsConfig extends ApprovalModsConfig {
        public AdminApprovalModsConfig(BaseClient client, boolean doPrompt, boolean enableQDL) {
            super(client, doPrompt);
            this.enableQDL = enableQDL;
        }

        boolean enableQDL = false;
    }

    @Override
    protected ApprovalModsConfig createApprovalModsConfig(InputLine inputLine, BaseClient client, boolean doPrompt) {
        boolean enableQDL = false;
        if (inputLine.hasArg(APPROVAL_QDL_ENABLE)) {
            enableQDL = true;
            inputLine.removeSwitch(APPROVAL_QDL_ENABLE);
        }
        return new AdminApprovalModsConfig(client, doPrompt, enableQDL);
    }

    @Override
    protected BaseClient doApprovalMods(ApprovalModsConfig approvalModsConfig) throws IOException {
        // Fix https://github.com/ncsa/oa4mp/issues/109
        AdminClient adminClient = (AdminClient) approvalModsConfig.client;
        if (approvalModsConfig.doPrompt) {
            adminClient.setAllowQDL("y".equals(getInput("Allow QDL in scripts?(y/n)", adminClient.isAllowQDL() ? "y" : "n")));
        } else {
            adminClient.setAllowQDL(((AdminApprovalModsConfig) approvalModsConfig).enableQDL);
        }
        return adminClient;
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        int updateCount = 0;
        List<Permission> permissions = getEnvironment().getPermissionStore().getByAdminID(oldID);
        if (!copy) {
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
