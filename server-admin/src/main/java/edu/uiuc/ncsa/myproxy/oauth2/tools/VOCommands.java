package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VOSerializationKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VOStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.util.SigningCommands;
import edu.uiuc.ncsa.myproxy.oauth2.base.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.util.SigningCommands.RS_256;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/22/21 at  8:01 AM
 */
public class VOCommands extends StoreCommands2 {
    public VOCommands(MyLoggingFacade logger, String defaultIndent, Store store) throws Throwable {
        super(logger, defaultIndent, store);
    }

    protected VOStore getVOS() {
        return (VOStore) getStore();
    }

    public VOCommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "  vo";
    }

    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {
        super.extraUpdates(identifiable, magicNumber);
        VirtualOrganization vo = (VirtualOrganization) identifiable;
        VOSerializationKeys keys = (VOSerializationKeys) getSerializationKeys();
        vo.setTitle(getPropertyHelp(keys.title(), "enter the title", vo.getTitle()));
        vo.setIssuer(getPropertyHelp(keys.issuer(), "enter the issuer", vo.getIssuer()));
        vo.setValid(getPropertyHelp(keys.valid(), "is this valid?", Boolean.toString(vo.isValid())).equalsIgnoreCase("y"));
        String iss = vo.getAtIssuer();
        if (iss == null) {
            iss = vo.getIssuer(); //default is they are equal
        }
        vo.setAtIssuer(getPropertyHelp(keys.atIssuer(), "enter the access token issuer", iss));
        vo.setDiscoveryPath(getPropertyHelp(keys.discoveryPath(), "enter the discovery path. NOTE this should be of the form host/path e.g.cilogon.org/ligo:", vo.getDiscoveryPath()));
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
                String rc = getPropertyHelp(keys.jsonWebKeys(), "Did you want to create a new set?", "n");
                if (rc.trim().toLowerCase().equals("y")) {
                    String type = readline("enter type RSA or EC:");
                    type = type.toUpperCase();
                    if (type.equals("RSA")) {
                        int keySize = 2048;
                        String raw = readline("Enter key size (default is" + keySize + ")");
                        try {
                            keySize = Integer.parseInt(raw);
                        } catch (Throwable t) {
                            say("sorry but \"" + raw + "\" is not an integer");
                            return;
                        }
                        try {
                            newKeys(vo, keySize);
                        } catch (Throwable t) {
                            say("That did not work:" + t.getMessage());
                            if (DebugUtil.isEnabled()) {
                                t.printStackTrace();
                            }
                            return;
                        }
                    }
                    if (type.equals("EC")) {
                        String curve = readline("Enter the curve you want to use (default is P-256)");
                        if (isTrivial(curve)) {
                            curve = JWKUtil2.EC_CURVE_P_256;
                        }
                        try {
                            newKeys(vo, curve);
                        } catch (Throwable e) {
                            say("That did not work:" + e.getMessage());
                            if (DebugUtil.isEnabled()) {
                                e.printStackTrace();
                            }
                        }
                        return;
                    }
                        say("Sorry but \"" + type + "\" is not a valid type of key");

                }
            }
        }
        String defaultKey = null;
        if (vo.getJsonWebKeys() != null) {
            for (String keyID : vo.getJsonWebKeys().keySet()) {
                JSONWebKey jsonWebKey = vo.getJsonWebKeys().get(keyID);
                if (jsonWebKey.algorithm.equals(RS_256)) {
                    defaultKey = jsonWebKey.id;
                    break;
                }
            }
        }
        vo.setDefaultKeyID(getPropertyHelp(keys.defaultKeyID(), "enter the default key id", defaultKey));

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
        int keySize = 2048;
        boolean isEllipticCurve = inputLine.hasArg("-ec");
        String curve = JWKUtil2.EC_CURVE_P_256;
        inputLine.removeSwitch("-ec");
        if (isEllipticCurve) {
            if (inputLine.hasArg("-curve")) {
                curve = inputLine.getNextArgFor("-curve");
                inputLine.removeSwitchAndValue("-curve");
            }
        } else {
            if (inputLine.hasArg("-size")) {
                try {
                    keySize = inputLine.getNextIntArg("-size");
                    inputLine.removeSwitchAndValue("-size");
                } catch (Throwable t) {
                    say("sorry, but " + inputLine.getNextArgFor("-size") + " is not a number");
                    return;
                }
            }

        }
        VirtualOrganization vo = (VirtualOrganization) id;
        if (vo.getJsonWebKeys() != null) {
            String ok = getInput("Did you want to overwrite the current set of keys?(y/n)", "n");
            if (ok.trim().equalsIgnoreCase("y")) {
                if (isEllipticCurve) {
                    newKeys(vo, curve);
                } else {
                    newKeys(vo, keySize);
                }
                String defaultId = null;
                for (JSONWebKey key : vo.getJsonWebKeys().values()) {
                    if (key.algorithm.equals(JWKUtil2.RS_256) || key.algorithm.equals(JWKUtil2.ES_256)) {
                        defaultId = key.id;
                    }
                }
                String newID = getInput("Set the new default key", defaultId == null ? "" : defaultId);
                vo.setDefaultKeyID(newID);
                getStore().save(vo);
                say("new keys saved");
            } else {
                say("aborted...");
                info("new keys aborted by user.");
            }
        }
    }

    protected void newKeys(VirtualOrganization vo, int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKeys jsonWebKeys = SigningCommands.createRSAJsonWebKeys(keySize);
        vo.setJsonWebKeys(jsonWebKeys);
        printJWK(jsonWebKeys);

    }

    protected void newKeys(VirtualOrganization vo, String curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKeys jsonWebKeys = SigningCommands.createECJsonWebKeys(curve);
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
    protected String format(Identifiable identifiable) {
        VirtualOrganization vo = (VirtualOrganization) identifiable;
        return vo.getIdentifierString() + " title:" + vo.getTitle() + " create time: " + vo.getCreationTS();
    }

    @Override
    public void bootstrap() throws Throwable {
        super.bootstrap();
        getHelpUtil().load("/help/vo_help.xml");
    }
}
