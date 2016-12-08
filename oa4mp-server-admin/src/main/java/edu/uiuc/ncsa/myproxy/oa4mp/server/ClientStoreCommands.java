package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.BaseClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/21/13 at  4:21 PM
 */
public class ClientStoreCommands extends BaseClientStoreCommands{
    public ClientStoreCommands(MyLoggingFacade logger, String defaultIndent, Store clientStore, ClientApprovalStore clientApprovalStore) {
        super(logger, defaultIndent, clientStore, clientApprovalStore);
    }


    public ClientStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
        setSortable(new ClientSorter());
    }

    @Override
    public String getName() {
        return "  clients";
    }




    @Override
    protected void longFormat(Identifiable identifiable) {
        super.longFormat(identifiable);
        Client client = (Client) identifiable;
        sayi("home uri=" + client.getHomeUri());
        sayi("error uri=" + client.getErrorUri());
        sayi("limited proxies? " + client.isProxyLimited());
    }

    @Override
    public void extraUpdates(Identifiable identifiable) {
        Client client = (Client) identifiable;
        client.setErrorUri(getInput("enter error uri", client.getErrorUri()));
        client.setHomeUri(getInput("enter home uri", client.getHomeUri()));
        client.setProxyLimited(isOk(getInput("does this client require limited proxies?", client.isProxyLimited() ? "y" : "n")));

        getPublicKeyFile((Client) identifiable);
    }

    @Override
    public boolean update(Identifiable identifiable) {

        Client client = (Client) identifiable;

        String newIdentifier = null;

        info("Starting client update for id = " + client.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");

        newIdentifier = getInput("enter the identifier", client.getIdentifierString());
        boolean removeCurrentClient = false;
        Identifier oldID = client.getIdentifier();

        // no clean way to do this.
        client.setName(getInput("enter the name", client.getName()));
        client.setEmail(getInput("enter email", client.getEmail()));
        client.setErrorUri(getInput("enter error uri", client.getErrorUri()));
        client.setHomeUri(getInput("enter home uri", client.getHomeUri()));
        client.setProxyLimited(isOk(getInput("does this client require limited proxies?", client.isProxyLimited() ? "y" : "n")));
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

    protected void getPublicKeyFile(Client client) {
        String input;
        String fileNotFoundMessage = INDENT + "...uh-oh, I can't find that file. Please enter it again";
        String secret = client.getSecret();

        if (!isEmpty(secret)) {
            secret = secret.substring(0, Math.min(25, secret.length())) + "...";
        }
        boolean askForFile = true;
        while (askForFile) {
            input = getInput("enter full path and file name of public key", secret);
            if (isEmpty(input)) {
                sayi("No file entered. Public key entry skipped");
                break;
            }
            if (input.equals(secret)) {
                sayi(" public key entry skipped.");
                break;
            }
            // if this is not the default value, then this *should* be the name of a file.
            if (input != null) {
                File f = new File(input);
                if (!f.exists()) {
                    say(fileNotFoundMessage);
                    continue;
                }
                try {
                    FileReader fr = new FileReader(f);
                    BufferedReader br = new BufferedReader(fr);
                    StringBuffer sb = new StringBuffer();
                    String x = br.readLine();
                    while (x != null) {
                        sb.append(x + "\n");
                        x = br.readLine();
                    }
                    br.close();
                    try {
                        KeyUtil.fromX509PEM(sb.toString());
                        askForFile = false;
                    } catch (GeneralException gx) {
                        gx.printStackTrace();
                        sayi("This does not seem to be in the correct format:" + gx.getMessage());
                        sayi("Please try again.");
                        continue;
                    }
                    client.setSecret(sb.toString());
                } catch (IOException e) {
                    say(fileNotFoundMessage);
                }
            }
        }
    }




}
