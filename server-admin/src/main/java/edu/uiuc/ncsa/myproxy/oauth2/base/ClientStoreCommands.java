package edu.uiuc.ncsa.myproxy.oauth2.base;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.ClientKeys;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/21/13 at  4:21 PM
 */
public class ClientStoreCommands extends BaseClientStoreCommands {
    public ClientStoreCommands(MyLoggingFacade logger,
                               String defaultIndent,
                               Store clientStore,
                               ClientApprovalStoreCommands clientApprovalStoreCommands) throws Throwable {
        super(logger, defaultIndent, clientStore, clientApprovalStoreCommands);
    }


    public ClientStoreCommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
        setSortable(new ClientSorter());
    }

    @Override
    public String getName() {
        return "  clients";
    }

    @Override
    protected int longFormat(Identifiable identifiable) {
        return longFormat(identifiable, false);
    }


    @Override
    public boolean update(Identifiable identifiable) throws IOException {

        Client client = (Client) identifiable;
        ClientKeys keys = (ClientKeys) getMapConverter().getKeys();

        String newIdentifier = null;

        info("Starting client update for id = " + client.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");

        newIdentifier = getPropertyHelp(keys.identifier(), "enter the identifier", client.getIdentifierString());
        boolean removeCurrentClient = false;
        Identifier oldID = client.getIdentifier();

        // no clean way to do this.
        client.setName(getPropertyHelp(keys.name(), "enter the name", client.getName()));
        client.setEmail(getPropertyHelp(keys.email(), "enter email", client.getEmail()));
        client.setErrorUri(getPropertyHelp(keys.errorURL(), "enter error url", client.getErrorUri()));
        client.setHomeUri(getPropertyHelp(keys.homeURL(), "enter home url", client.getHomeUri()));
        client.setProxyLimited(isOk(getPropertyHelp(keys.proxyLimited(), "does this client require limited proxies?", client.isProxyLimited() ? "y" : "n")));
        // set file not found message.
        extraUpdates(client, DEFAULT_MAGIC_NUMBER);
        sayi("here is the complete client:");
        longFormat(client);
        if (!newIdentifier.equals(client.getIdentifierString())) {
            //sayi2(" remove client with id=\"" + client.getIdentifier() + "\" [y/n]? ");
            removeCurrentClient = isOk(readline(" remove client with id=\"" + client.getIdentifier() + "\" [y/n]? "));
            client.setIdentifier(BasicIdentifier.newID(newIdentifier));
        }
        //sayi2("save [y/n]?");
        if (isOk(readline("save [y/n]?"))) {
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
    protected void doRename(Identifier srcID, Identifier targetID) {
        super.doRename(srcID, targetID);
        // Now fix approval
        cloneApproval(srcID, targetID);
        getClientApprovalStore().remove(srcID);

    }

    private void cloneApproval(Identifier srcID, Identifier targetID) {
        ClientApproval oldCA = (ClientApproval) getClientApprovalStore().get(srcID);
        ClientApproval newCA = (ClientApproval) oldCA.clone();
        newCA.setIdentifier(targetID);
        getClientApprovalStore().save(newCA);
    }

    @Override
    protected Identifier doCopy(Identifiable source, Identifier targetId, boolean useRandomID) {
        Identifier id = super.doCopy(source, targetId, useRandomID);
        cloneApproval(source.getIdentifier(), id);
        return id;
    }

    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {
        super.extraUpdates(identifiable, magicNumber);
        Client client = (Client)identifiable;
        ClientKeys keys = (ClientKeys) getMapConverter().getKeys();
        client.setHomeUri(getPropertyHelp(keys.homeURL(), "enter home url", client.getHomeUri()));
    }
}
