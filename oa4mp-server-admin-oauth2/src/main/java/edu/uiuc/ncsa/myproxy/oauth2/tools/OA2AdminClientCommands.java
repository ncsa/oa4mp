package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.BaseClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  12:34 PM
 */
public class OA2AdminClientCommands extends BaseClientStoreCommands {
    public OA2AdminClientCommands(MyLoggingFacade logger,
                                  String defaultIndent,
                                  Store clientStore,
                                  ClientApprovalStore clientApprovalStore,
                                  PermissionsStore permissionsStore) {
        super(logger, defaultIndent, clientStore, clientApprovalStore);
        this.permissionsStore = permissionsStore;
    }

    @Override
    public String getName() {
        return "  admins";
    }

    PermissionsStore permissionsStore;

    @Override
    protected void longFormat(Identifiable identifiable) {
        super.longFormat(identifiable);
        AdminClient client = (AdminClient) identifiable;
        sayi("issuer=" + client.getIssuer());
        sayi("vo=" + client.getVirtualOrganization());
    }

    @Override
    public void extraUpdates(Identifiable identifiable) {
        AdminClient client = (AdminClient) identifiable;
        String secret = client.getSecret();
        String input;
        boolean askForSecret = true;


        while (askForSecret) {
            input = getInput("enter a new secret or return to skip.", secret);
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
        String vo = getInput("Give the VO", client.getVirtualOrganization());
        if (!isEmpty(vo)) {
            client.setVirtualOrganization(vo);
        }

    }

    protected void showListClientsHelp() {
        say("list_clients id|index - list all the clients this administrator manages");
        say("                       This also lists if the client with the given id has been approved.");
    }

    // For CIL-508
    public void list_clients(InputLine inputLine) throws Exception{
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
        if(clients == null || clients.isEmpty()){
            say("(none)");
        }
        for (Identifier identifier : clients) {
            say("(" + (getClientApprovalStore().isApproved(identifier)?"Y":"N") + ") " + identifier);
        }

    }


    protected void showListAdminsHelp(){
        say("list_admins id - list the administrators associated with the given client id");
        say("                 Note that you need the actual identifier for the client, not an index.");
    }
    public void list_admins(InputLine inputLine) throws Exception{
        if(showHelp(inputLine)){
            showListAdminsHelp();
            return;
        }
        Identifier clientID  = null;
        try {
            String rawID = inputLine.getLastArg();
            if(rawID.startsWith("/")){
                // if they supply a leading / just drop it, since the user is being consistent with other cases.
                rawID = rawID.substring(1);
            }
            clientID = BasicIdentifier.newID(rawID);
        }catch(Throwable t){
            say("Sorry, \"" + inputLine.getLastArg() + "\" is not a valid identifier. " + t.getMessage());
            return;
        }
        List<Identifier> admins = permissionsStore.getAdmins(clientID);
        if(admins == null || admins.isEmpty()){
            say("(none)");
            return;
        }
        for(Identifier id : admins){
            AdminClient adminClient = (AdminClient)getStore().get(id);
            say(format(adminClient, (ClientApproval) getClientApprovalStore().get(adminClient.getIdentifier())));
        }

    }
    @Override
    protected void showDeserializeHelp() {
        super.showDeserializeHelp();
        say("NOTE that for clients, the assumption is that you are supplying the hashed secret, not the actual secret.");
        say("If you need to create a hash of a secret, invoke the create_hash method on the secret");
    }

    @Override
    protected void addEntry(Identifiable identifiable, JSONObject json) {
        
    }

    @Override
    protected void removeEntry(Identifiable identifiable, JSONObject json) {

    }


}
