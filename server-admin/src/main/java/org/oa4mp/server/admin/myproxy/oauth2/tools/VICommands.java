package org.oa4mp.server.admin.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import org.oa4mp.server.admin.myproxy.oauth2.base.OA4MPStoreCommands;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VISerializationKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VIStore;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.loader.qdl.util.SigningCommands;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/22/21 at  8:01 AM
 */
public class VICommands extends OA4MPStoreCommands {

    public static final String EC_FLAG = "-ec";
    public static final String RSA_SIZE_FLAG = "-size";
    public static final String EC_CURVE_FLAG = "-curve";

    public VICommands(MyLoggingFacade logger, String defaultIndent, Store store) throws Throwable {
        super(logger, defaultIndent, store);
    }

    protected VIStore getVIS() {
        return (VIStore) getStore();
    }

    public VICommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "  vi";
    }

    @Override
    public void extraUpdates(Identifiable identifiable, int magicNumber) throws IOException {
        super.extraUpdates(identifiable, magicNumber);
        VirtualIssuer vi = (VirtualIssuer) identifiable;
        VISerializationKeys keys = (VISerializationKeys) getSerializationKeys();
        if (vi.getCreationTS() == null) {
            vi.setCreationTS(new Date());
        }
        vi.setTitle(getPropertyHelp(keys.title(), "enter the title", vi.getTitle()));
        vi.setIssuer(getPropertyHelp(keys.issuer(), "enter the issuer", vi.getIssuer()));
        String iss = vi.getAtIssuer();
        if (iss == null) {
            iss = vi.getIssuer(); //default is they are equal
        }
        vi.setAtIssuer(getPropertyHelp(keys.atIssuer(), "enter the access token issuer", iss));
        vi.setDiscoveryPath(getPropertyHelp(keys.discoveryPath(), "enter the discovery path. NOTE this should be of the form host/path e.g.cilogon.org/ligo:", vi.getDiscoveryPath()));
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
                                vi.setJsonWebKeys(jsonWebKeys);
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
                    String type = getInput("enter type RSA or EC:", "RSA");
                    type = type.toUpperCase();
                    if (type.equals("RSA")) {
                        int keySize = 2048;
                        String raw = readline("Enter key size (default is " + keySize + ")");
                        try {
                            if (!StringUtils.isTrivial(raw)) {
                                keySize = Integer.parseInt(raw);
                            }
                        } catch (Throwable t) {
                            say("sorry but \"" + raw + "\" is not an integer");
                            return;
                        }
                        try {
                            newKeys(vi, keySize);
                        } catch (Throwable t) {
                            say("That did not work:" + t.getMessage());
                            if (DebugUtil.isEnabled()) {
                                t.printStackTrace();
                            }
                            return;
                        }
                    } else {
                        if (type.equals("EC")) {
                            String curve = readline("If you do not want the default curves used, enter a specific one:");

                            try {
                                newKeys(vi, curve);
                            } catch (Throwable e) {
                                say("That did not work:" + e.getMessage());
                                if (DebugUtil.isEnabled()) {
                                    e.printStackTrace();
                                }
                                return;
                            }
                        } else {
                            say("Sorry but \"" + type + "\" is not a valid type of key");
                        }
                    }
                }
            }
        }
        String defaultKey = null;
        if (vi.getJsonWebKeys() != null) {
            defaultKey = vi.getJsonWebKeys().getDefaultKeyID();
        }
        vi.setDefaultKeyID(getPropertyHelp(keys.defaultKeyID(), "enter the default key id", defaultKey));
        vi.setCreationTS(new Date());
        vi.setLastModifiedTS(new Date());
        // could ask if they really want it to be valid, but don't
        //vi.setValid(getPropertyHelp(keys.valid(), "is this valid?", Boolean.toString(vi.isValid())).equalsIgnoreCase("y"));
        vi.setValid(true);
    }

    public void new_keys(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("new_keys [id]");
            sayi("Create a completely new set of keys for a virtual issuer.");
            sayi("You can create a default set of RSA keys with no arguments");
            sayi("A complete set of default elliptic curve keys is done with the " + EC_FLAG);
            sayi("E.g: Generate a new set of default elliptic curve keys");
            sayi("new_keys " + EC_FLAG);
            sayi("This creates a set of keys for the P-256 curve and algorithm ES256, P-384 and ES384, and P-521 and ES512");
            sayi("E.g: Generate a new set of RSA keys of 4096 bits");
            sayi("new_keys " + RSA_SIZE_FLAG + " 4096");
            sayi("E.g: Generate a new set of elliptic curve keys for a specific curve");
            sayi("new_keys " + EC_FLAG + " " + EC_CURVE_FLAG + " P-384");
            sayi("This creates a set of keys using the curve P-384 and the algorithms ES256, ES384 and ES512");

            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("sorry, no such virtual issuer");
            return;
        }      if(!identifiables.isSingleton()){
            say("only a single object is supported by this operation");
            return;
        }

        int keySize = 2048;
        boolean isEllipticCurve = inputLine.hasArg(EC_FLAG);
        String curve = null; // default
        inputLine.removeSwitch(EC_FLAG);
        if (isEllipticCurve) {
            if (inputLine.hasArg(EC_CURVE_FLAG)) {
                curve = inputLine.getNextArgFor(EC_CURVE_FLAG);
                inputLine.removeSwitchAndValue(EC_CURVE_FLAG);
            }
        } else {
            if (inputLine.hasArg(RSA_SIZE_FLAG)) {
                try {
                    keySize = inputLine.getNextIntArg(RSA_SIZE_FLAG);
                    inputLine.removeSwitchAndValue(RSA_SIZE_FLAG);
                } catch (Throwable t) {
                    say("sorry, but " + inputLine.getNextArgFor(RSA_SIZE_FLAG) + " is not a number");
                    return;
                }
            }

        }
        VirtualIssuer vo = (VirtualIssuer) identifiables.get(0);
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

    protected void newKeys(VirtualIssuer vo, int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKeys jsonWebKeys = SigningCommands.createRSAJsonWebKeys(keySize, null);
        vo.setJsonWebKeys(jsonWebKeys);
        printJWK(jsonWebKeys);

    }

    protected void newKeys(VirtualIssuer vo, String curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKeys jsonWebKeys;
        if (StringUtils.isTrivial(curve)) {
            jsonWebKeys = SigningCommands.createECJsonWebKeys(null);
        } else {
            jsonWebKeys = SigningCommands.createECJsonWebKeys(curve, null);
        }
        vo.setJsonWebKeys(jsonWebKeys);
        printJWK(jsonWebKeys);
    }

    /**
     * Create the new keys with the spec default. Note that this requires difference curves for each
     * size.
     *
     * @param vo
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    protected void newKeys(VirtualIssuer vo) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        newKeys(vo, null); // do the spec default
    }

    public void print_keys(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("print_keys");
            sayi("Print a quick summary of the JSON Web keys");
            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("sorry, no such virtual issuer");
            return;
        }        if(!identifiables.isSingleton()){
            say("only single object are supported");
            return;
        }

        VirtualIssuer vo = (VirtualIssuer) identifiables.get(0);
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
        VirtualIssuer vo = (VirtualIssuer) identifiable;
        return vo.getIdentifierString() + " (" + vo.getTitle() + ") created on " + vo.getCreationTS();
    }

    @Override
    public void bootstrap(InputLine inputLine) throws Throwable {
        super.bootstrap(inputLine);
    }

    @Override
    protected void initHelp() throws Throwable {
        super.initHelp();
        getHelpUtil().load("/help/vi_help.xml");
    }

    public void add_admin(InputLine inputLine) throws Throwable{
        if(showHelp(inputLine)){
            say("add_admin admin_id [vi_id] - add the admin client or a result set of them ");
            say("to the current or given virtual issuer");
            printIndexHelp(true);
            return;
        }
List<Identifiable> identifiables = findByIDOrRS(getEnvironment().getAdminClientStore(), inputLine.getArg(1));
        if(identifiables == null){
            say("no admin id could be found.");
            return;
        }
        int count = 0;
        Identifiable vi = findSingleton(inputLine, "virtual issuer not found");
        for(Identifiable identifiable: identifiables){
            AdminClient adminClient = (AdminClient) identifiable;
            adminClient.setVirtualIssuer(vi.getIdentifier());
            adminClient.setExternalVIName(vi.getIdentifierString());
            getEnvironment().getAdminClientStore().save(adminClient);
            count++;
        }
        say(count + " admin clients added to virtual issuer \"" + vi.getIdentifierString() + "\"");
    }

    /* There should be no permissions in the store that are updated. VIs are not directly referenced
      in permissions.
     */
    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        return 0;
    }

    @Override
    public ChangeIDRecord doChangeID(Identifiable identifiable, Identifier newID, boolean updatePermissions) {
        ChangeIDRecord changeIDRecord = super.doChangeID(identifiable, newID, updatePermissions);
        Identifier oldID = changeIDRecord.oldID;
        // now we have to find the admin records that use this
        AdminClientKeys adminClientKeys = new AdminClientKeys();
        List<AdminClient> admins = getEnvironment().getAdminClientStore().search(adminClientKeys.vo(),oldID.toString(), false);
        for(AdminClient adminClient: admins){
            adminClient.setVirtualIssuer(newID);
            if(adminClient.getExternalVIName().equals(oldID.toString())){
                adminClient.setExternalVIName(newID.toString());
            };
            getEnvironment().getAdminClientStore().save(adminClient);
        }
        changeIDRecord.updateCount = changeIDRecord.updateCount +admins.size();
        return changeIDRecord;
    }
    public void list_admins(InputLine inputLine) throws Throwable {
        if(showHelp(inputLine)){
            say("list_admins [-rs name] id - list the admin IDs for the current VI.");
            say("You may save them in a result set if you want.");
            say("This is restricted to a single VI.");
            return;
        }
        Identifiable identifiable = findSingleton(inputLine);
        if (identifiable == null) {
            say("no VI found.");
            return;
        }
        String rsName = null;
        boolean hasRS = inputLine.hasArg(RESULT_SET_KEY);
        if(hasRS){
            rsName = inputLine.getNextArgFor(RESULT_SET_KEY);
            inputLine.removeSwitchAndValue(RESULT_SET_KEY);
        }
        AdminClientKeys adminClientKeys = new AdminClientKeys();
        List<AdminClient> admins  = getEnvironment().getAdminClientStore().search(adminClientKeys.vo(),identifiable.getIdentifierString(), false);
        if(hasRS) {
            List<Identifiable> hackyList = new ArrayList<Identifiable>(admins.size());
            hackyList.addAll(admins); // since java won't allow certain casts.
            RSRecord rsRecord = new RSRecord(hackyList, adminClientKeys.allKeys());
            getResultSets().put(rsName, rsRecord);
        }
        for(AdminClient adminClient: admins){
            say(adminClient.getIdentifierString());
        }
        say("found " + admins.size() + " admin clients");

    }
}
