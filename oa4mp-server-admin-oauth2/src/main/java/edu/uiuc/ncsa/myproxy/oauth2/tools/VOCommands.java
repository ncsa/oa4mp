package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VOStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/22/21 at  8:01 AM
 */
public class VOCommands extends StoreCommands2 {
    public VOCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    protected VOStore getVOS() {
        return (VOStore) getStore();
    }

    public VOCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "  vo";
    }

    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        VirtualOrganization vo = (VirtualOrganization) identifiable;
        String newIdentifier = null;
        info("Starting VO update for id = " + vo.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");
        newIdentifier = getInput("enter the identifier", vo.getIdentifierString());
        boolean removeCurrentVO = false;
        Identifier oldID = vo.getIdentifier();

        vo.setTitle(getInput("enter the title", vo.getTitle()));
        vo.setIssuer(getInput("enter the issuer", vo.getIssuer()));
        vo.setAtIssuer(getInput("enter the access token issuer (if different)", vo.getAtIssuer()));
        vo.setDiscoveryPath(getInput("enter the discovery path", vo.getDiscoveryPath()));
        String ok = getInput("Did you want to specify a file with the JSON web keys(y/n)", "n");
        if (!isTrivial(ok)) {
            if (ok.trim().toLowerCase().equals("y")) {
                String filePath = readline("Enter full path to the file:");
                File f = new File(filePath);
                if (f.exists()) {
                    if (f.isFile()) {
                        if (f.canRead()) {
                            try {
                                JSONWebKeys jsonWebKeys = JSONWebKeyUtil.fromJSON(f);
                                vo.setJsonWebKeys(jsonWebKeys);
                                printJWK(jsonWebKeys);
                            } catch (Throwable e) {
                                if (DebugUtil.isEnabled()) {
                                    e.printStackTrace();
                                }
                                say("Sorry, there was a problem reading the file::" + e.getMessage());
                            }
                        } else {
                            say("Sorry but you don't have permission to read \"" + f.getAbsolutePath() + "\".");
                        }
                    } else {
                        say("Sorry but \"" + f.getAbsolutePath() + "\" is not a file.");
                    }
                } else {
                    say("Sorry but \"" + f.getAbsolutePath() + "\" does not exist.");
                }

            } else {
                String rc = getInput("Did you want to create a new set?", "n");
                if (rc.trim().toLowerCase().equals("y")) {
                    try {
                        newKeys(vo);
                    } catch (Throwable e) {
                        if (DebugUtil.isEnabled()) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        String defaultKey = null;
        if (vo.getJsonWebKeys() != null) {
            for (String keyID : vo.getJsonWebKeys().keySet()) {
                JSONWebKey jsonWebKey = vo.getJsonWebKeys().get(keyID);
                if (jsonWebKey.algorithm.equals(SigningCommands.RS_256)) {
                    defaultKey = jsonWebKey.id;
                    break;
                }
            }
        }
        vo.setDefaultKeyID(getInput("enter the default key id", defaultKey));
        extraUpdates(vo);
        sayi("here is the complete virtual organization (VO):");
        longFormat(vo);
        if (!newIdentifier.equals(vo.getIdentifierString())) {
            //  sayi2(" remove client with id=\"" + client.getIdentifier() + "\" [y/n]? ");
            removeCurrentVO = isOk(readline(" remove VO with id=\"" + vo.getIdentifier() + "\" [y/n]? "));
            vo.setIdentifier(BasicIdentifier.newID(newIdentifier));
        }
        //  sayi2("save [y/n]?");
        if (isOk(readline("save [y/n]?"))) {
            //getStore().save(client);
            if (removeCurrentVO) {
                info("removing VO with id = " + oldID);
                getStore().remove(vo.getIdentifier());
                sayi("VO with id " + oldID + " removed. Be sure to save any changes.");
            }
            sayi("VO updated.");
            info("VO with id " + vo.getIdentifierString() + " saving...");

            return true;
        }
        sayi("VO not updated, losing changes...");
        info("User terminated updates for VO with id " + vo.getIdentifierString());
        return false;

    }

    public void new_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("new_keys");
            sayi("Create a completely new set of keys,");
            return;
        }
        Identifiable id = findItem(inputLine);
        if (id == null) {
            say("sorry, no such VO");
            return;
        }
        VirtualOrganization vo = (VirtualOrganization) id;
        if (vo.getJsonWebKeys() != null) {
            String ok = getInput("Did you want to overwrite the current set of keys?(y/n)", "n");
            if (ok.trim().toLowerCase().equals("y")) {
                newKeys(vo);
                getStore().save(vo);
                say("new keys saved");
            } else {
                say("aborted...");
                info("new keys aborted by user.");
            }
        }
    }

    protected void newKeys(VirtualOrganization vo) throws NoSuchProviderException, NoSuchAlgorithmException {
        JSONWebKeys jsonWebKeys = SigningCommands.createJsonWebKeys();
        vo.setJsonWebKeys(jsonWebKeys);
        printJWK(jsonWebKeys);
    }

    public void print_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("print_keys");
            sayi("Print a quick summary of the JSON Web keys");
            return;
        }
        Identifiable id = findItem(inputLine);
        if (id == null) {
            say("sorry, no such VO");
            return;
        }
        VirtualOrganization vo = (VirtualOrganization) id;
        if (vo.getJsonWebKeys() == null) {
            say("sorry, no JSON web keys set.");
            return;
        }
        printJWK(vo.getJsonWebKeys());
    }

    private void printJWK(JSONWebKeys jsonWebKeys) {
        say("Found keys are:");
        for (String key_id : jsonWebKeys.keySet()) {
            JSONWebKey jsonWebKey = jsonWebKeys.get(key_id);
            String out = jsonWebKey.id + ": alg =" + jsonWebKey.algorithm;
            if (!isTrivial(jsonWebKey.use)) {
                out = out + ", use=" + jsonWebKey.use;
            }
            sayi(out);
        }
    }

    @Override
    public void extraUpdates(Identifiable identifiable) throws IOException {

    }

    @Override
    protected String format(Identifiable identifiable) {
        VirtualOrganization vo = (VirtualOrganization) identifiable;
        return vo.getIdentifierString() + " title:" + vo.getTitle() + " create time: " + vo.getCreated();
    }
}
