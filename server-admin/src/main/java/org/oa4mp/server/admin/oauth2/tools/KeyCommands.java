package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.ArgumentNotFoundException;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.configuration.TimeUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import org.oa4mp.server.admin.oauth2.base.OA4MPStoreCommands;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.keys.KEConfiguration;
import org.oa4mp.server.loader.oauth2.storage.keys.KERecord;
import org.oa4mp.server.loader.oauth2.storage.keys.KEStore;
import org.oa4mp.server.loader.oauth2.storage.keys.KEStoreUtilities;
import org.oa4mp.server.loader.oauth2.storage.vi.VISerializationKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VIStore;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.loader.qdl.util.SigningCommands;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static edu.uiuc.ncsa.security.core.util.StringUtils.*;
import static org.oa4mp.server.loader.oauth2.OA2SE.SERVER_VI_ID;
import static org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader.GRACE_PERIOD_NOT_CONFIGURED;
import static org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader.MAX_ACCESS_TOKEN_LIFETIME_DEFAULT;
import static org.oa4mp.server.loader.oauth2.storage.keys.KEStoreUtilities.jwksToIDMap;

public class KeyCommands extends OA4MPStoreCommands {

    public static final String DEFAULT_SERVER_VI = "default";

    public KeyCommands(CLIDriver driver, String defaultIndent, OA2SE oa2SE) throws Throwable {
        super(driver, defaultIndent, null);
        setEnvironment(oa2SE);
    }

    public KeyCommands(CLIDriver driver, OA2SE oa2SE) throws Throwable {
        super(driver, null);
        setEnvironment(oa2SE);
    }

    @Override
    public KEStore<KERecord> getStore() {
        return getEnvironment().getKEStore();
    }

    @Override
    protected String format(Identifiable identifiable) {
        return null;
    }

    @Override
    protected String format(Identifiable identifiable, int offset, int[] fieldWidths) {
        KERecord keRecord = (KERecord) identifiable;
        int width = 25; // long width, for ISO dates e.g.
        int s = 5; // short width
        String out = LJustify((keRecord.getDefault() ? "*" : "") + keRecord.getKid(), fieldWidths[0]) +
                STILE + LJustify(keRecord.getAlg(), fieldWidths[1]) +
                STILE + LJustify(keRecord.getUse(), fieldWidths[2]) +
                STILE + (keRecord.getValid() ? "true " : "false") + // make length match
                STILE + center((keRecord.getNbf() == null ? "--" : Iso8601.date2String(keRecord.getNbf())), fieldWidths[4]) +
                STILE + center((keRecord.getExp() == null ? "--" : Iso8601.date2String(keRecord.getExp())), fieldWidths[5]) +
                STILE + LJustify(keRecord.getVi() == null ? "--" : keRecord.getVi().toString(), fieldWidths[6]) +
                STILE + keRecord.getIdentifierString();
        return out;
    }

    @Override
    public int[] fieldWidths(List<Identifiable> identifiables) {
        int width = 25; // long width, for ISO dates e.g.
        int s = 5; // short width
        if (identifiables == null || 100 < identifiables.size()) {
            return new int[]{33, s, s, s, width, width, 32};
        }
        int[] fieldWidths = new int[]{5, s, s, s, width, width, 5};
        for (Identifiable identifiable : identifiables) {
            KERecord keRecord = (KERecord) identifiable;
            if (!isTrivial(keRecord.getKid())) {
                fieldWidths[0] = Math.max(fieldWidths[0], keRecord.getKid().length());
            }
            if (keRecord.getVi() != null) {
                fieldWidths[6] = Math.max(fieldWidths[6], keRecord.getVi().toString().length());
            }
        }
        fieldWidths[0] = fieldWidths[0] + 1; // since it may get a * if its a  default key
        return fieldWidths;
    }

    @Override
    protected String columnHeader(int offset, int[] fieldWidths) {
        int width = 25; // long width, for ISO dates e.g.
        int s = 5; // short width
        String out = StringUtils.getBlanks(offset + 2);
        int i = 0;
        out = out + pad2("kid", fieldWidths[i++]) +
                STILE + pad2("alg", fieldWidths[i++]) +
                STILE + pad2("use", fieldWidths[i++]) +
                STILE + pad2("valid", fieldWidths[i++]) +
                STILE + pad2("not before", fieldWidths[i++]) +
                STILE + pad2("expires", fieldWidths[i++]) +
                STILE + pad2("VI", fieldWidths[i]) +
                STILE + "identifier";
        return out;
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        return 0;
    }

    @Override
    public String getName() {
        return "keys";
    }

    /**
     * Migrate a list of VIs keys into the store. Note that if the store contains
     * the given keys already, this will update the records as needed.
     *
     * @param foundIdentifiables
     * @param removeFromVI       -- if true, remove the keys in the VI
     * @return returns list of un-migrated ids
     */
    public List<Identifier> migrate(FoundIdentifiables foundIdentifiables, boolean removeFromVI) {
        VIStore viStore = getEnvironment().getVIStore();
        HashSet<Identifier> viIDs = viStore.keySet();
        boolean doAll = foundIdentifiables == null;
        List<Identifier> ignoredVIRecords = new ArrayList<>();
        Map<Identifier, KERecord> newKERecords = new HashMap<>();
        Map<Identifier, KERecord> updateKERecords = new HashMap<>();
        Map<Identifier, VirtualIssuer> updateVIRecords = new HashMap<>();
        // we need to update or create records
        HashSet<String> allKIDs = getStore().getKIDs();
        int count = 0;
        if (doAll) {
            count = viIDs.size();
        } else {
            count = foundIdentifiables.size();
        }
        for (int i = 0; i < count; i++) {
            VirtualIssuer vi;
            if (doAll) {
                vi = (VirtualIssuer) viStore.get(viIDs.iterator().next());
            } else {
                vi = (VirtualIssuer) foundIdentifiables.get(i);
            }
            if (vi.getJsonWebKeys() == null) {
                ignoredVIRecords.add(vi.getIdentifier()); // no keys, so skip.
                continue;
            }

            JSONWebKeys jsonWebKeys = vi.getJsonWebKeys();
            for (String kid : jsonWebKeys.keySet()) {
                JSONWebKey jsonWebKey = jsonWebKeys.get(kid);
                KERecord keRecord;
                boolean hasKID = allKIDs.contains(kid);
                if (hasKID) {
                    keRecord = getStore().getByKID(kid);
                } else {
                    keRecord = getStore().create();
                    keRecord.setValid(true);
                    keRecord.setVi(vi.getIdentifier().getUri());// if it's in the VI record, it's implicitly valid
                }
                try {
                    boolean tempIsValid = keRecord.getValid();
                    keRecord.fromJWK(jsonWebKey, vi.getDefaultKeyID().equals(kid));
                    keRecord.setValid(tempIsValid); // preserve the validity of the record.
                    // Now we make sure the appropriate accounting information is in place
                    // with defaults if not present.
                    if (keRecord.getIat() == null) {
                        keRecord.setIat(new Date());
                    }
                    if (keRecord.getNbf() == null) {
                        keRecord.setNbf(new Date());
                    }
                    if (keRecord.getVi() == null || !keRecord.getVi().equals(vi.getIdentifier().getUri())) {
                        keRecord.setVi(vi.getIdentifier().getUri());// if its in the VI record, it's implicitly valid
                    }
                } catch (Throwable e) {
                    if (isDebugOn()) {
                        e.printStackTrace();
                    }
                    ignoredVIRecords.add(vi.getIdentifier()); // no keys, so skip.
                    continue;
                }
                // Remember that putAll for the store will only decide whether to update or create
                // records based on the identifier. We, however, need to check if the key is already in the store
                // by kid.
                if (hasKID) {
                    updateKERecords.put(keRecord.getIdentifier(), keRecord);
                } else {
                    newKERecords.put(keRecord.getIdentifier(), keRecord);
                }
                if (removeFromVI) {
                    vi.setJsonWebKeys(null);
                    vi.setDefaultKeyID(null);
                    updateVIRecords.put(vi.getIdentifier(), vi);
                }
            }
            if (removeFromVI) {
                getEnvironment().getVIStore().update(updateVIRecords);
            }
        }
        if (0 < newKERecords.size()) {
            getStore().putAll(newKERecords); // remember that putAll will update or create as needed.
        }
        if (0 < updateKERecords.size()) {
            getStore().update(updateKERecords);
        }
        return ignoredVIRecords;
    }

    public static final String MIGRATE_LIST = "-list";
    public static final String MIGRATE_ALL_VIS = "-all";
    public static final String MIGRATE_CLEANUP = "-cleanup";
    public static final String MIGRATE_SERVER_KEYS = "-server";

    protected void migrateHelp(InputLine line) {
        int width = 10;
        String name = getMethodName(4);
        say(name + " [" + MIGRATE_LIST + "] | [" + MIGRATE_CLEANUP + "] | [" +
                MIGRATE_ALL_VIS + " | vi_id][" + MIGRATE_SERVER_KEYS + "] -  migrate the keys stored in a VI to ");

        say("this store. Optionally remove them from the VI. Once migrated,");
        say("the system manages them and the keys stored in the VI (or server config file) are ignored");
        say(RJustify(MIGRATE_SERVER_KEYS, width) + " = Migrate the keys in the server configuration to the store. This cannot be combined with other flags.");
        say(RJustify(MIGRATE_LIST, width) + " = return a list of VIs that have stored keys.");
        say(RJustify("vi_id", width) + " = migrate the keys stored in the given VI only.");
        say(RJustify(MIGRATE_ALL_VIS, width) + " = migrate all VI keys to this store.");
        say(RJustify(MIGRATE_CLEANUP, width) + " = remove the keys stored in a VI.");
        say("This does allow for result sets as well for migration.");
        say("Keys must beion the store (with all of the correct accounting information) to be rotated.");
        say("Therefore rotating keys will inplicitly migrate them.");
        say("E.g. to migrate your keys from teh server configuration to the store.");
        say(name + " -server");
        say("6 keys migrated.");
    }

    public void migrate(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            migrateHelp(inputLine);
            return;
        }
        if (getEnvironment().getKEStore() == null) {
            say("No key store enabled.");
            return;
        }
        boolean listMigrated = inputLine.hasArg(MIGRATE_LIST);
        boolean migrateAll = inputLine.hasArg(MIGRATE_ALL_VIS);
        boolean cleanupMigrated = inputLine.hasArg(MIGRATE_CLEANUP);
        inputLine.removeSwitch(MIGRATE_LIST);
        inputLine.removeSwitch(MIGRATE_ALL_VIS);
        inputLine.removeSwitch(MIGRATE_CLEANUP);
        boolean migrateServerKeys = inputLine.hasArg(MIGRATE_SERVER_KEYS);
        inputLine.removeSwitch(MIGRATE_SERVER_KEYS);

        VIStore<VirtualIssuer> viStore = getEnvironment().getVIStore();

        // Intercept if they issue a call to do the default vi directly. They meant
        // to migrate the server keys.
        if(inputLine.hasLastArg() && (DEFAULT_SERVER_VI.equals(inputLine.getLastArg()) || SERVER_VI_ID.toString().equals(inputLine.getLastArg()))) {
            migrateServerKeys = true;
        }
        if (migrateServerKeys) {
            VirtualIssuer vi = viStore.get(SERVER_VI_ID);
            // if the default VI for the server does not exist, create it.
            // https://github.com/ncsa/oa4mp/issues/305
            if (vi == null) {
                vi = viStore.create();
                vi.setIdentifier(SERVER_VI_ID);
                vi.setTitle("Default issuer");
                vi.setValid(true);
                vi.setKeyRotationEnabled(true);
                vi.setAtGracePeriod(getEnvironment().getMaxATLifetime());
                vi.setCacheGracePeriod(24L * 3600 * 1000L);
                vi.setDescription("Default OA4MP Server Configuration");
                viStore.save(vi);
            }
            if (!getStore().getCurrentKeys(vi).isEmpty()) { // has keys in config. Contract is to move them
                vi.setJsonWebKeys(getEnvironment().getServerJWKS());
            } else {
                if (!vi.hasJWKs()) {
                    // no server keys in config, but there are keys in VI.
                    if (!"y".equals(readline("There are only server keys in the VI. Did you want to migrate them? (y/n)"))) {
                        say("Aborting migration");
                        return;
                    }
                    IdentifiableMap map = new IdentifiableMap();
                    for (String kid : getEnvironment().getServerJWKS().keySet()) {
                        JSONWebKey webKey = getEnvironment().getServerJWKS().get(kid);
                        map.put(KEStoreUtilities.createSingleKERecord(getStore(),
                                SERVER_VI_ID.getUri(), true, webKey, getEnvironment().getServerJWKS().getDefaultKeyID()));
                    }

                    getStore().putAll(new HashMap(map));
                    say("Migrated " + map.size() + " keys");
                    return;
                } else {
                    // no keys in server config, no keys in VI. So there are NO server keys
                    say("No server keys found anywhere. Please create them.");
                    return;
                }

            }

            FoundIdentifiables foundIdentifiables = new FoundIdentifiables(false);
            foundIdentifiables.add(vi);
            List<Identifier> ids = migrate(foundIdentifiables, false);
            say("skipped " + ids.size() + " keys");
            return;
        }
        if (listMigrated) {
            boolean firstOne = true;
            for (Object vid : viStore.keySet()) {
                VirtualIssuer vi = (VirtualIssuer) viStore.get(vid);
                if (vi.getJsonWebKeys() == null) continue;
                if (firstOne) {
                    say("VIs that have JWKs:");
                    firstOne = false;
                }
                String x = vi.getIdentifierString();
                if (x.indexOf("#version=") != -1) {
                    // don't list versions.
                    say(vi.getIdentifierString());
                }
            }
            return;
        }
        FoundIdentifiables foundVIs = null;
        if (migrateAll) {
            migrate(null, cleanupMigrated);
        } else {
            if (inputLine.hasArgs()) {
                foundVIs = findByIDOrRS(viStore, inputLine.getLastArg());
            }
            migrate(foundVIs, cleanupMigrated);
        }
        Map<Identifier, KERecord> newRecords = new HashMap<>();
        // case 1, do explicitly requested migration
        if (foundVIs != null && !foundVIs.isEmpty()) {
            int keysProcessed = 0;
            int visProcessed = 0;
            int visSkipped = 0;
            for (Identifiable identifiable : foundVIs) {
                VirtualIssuer vi = (VirtualIssuer) identifiable;
                if (!vi.hasJWKs()) {
                    visSkipped++;
                    continue;
                }
                JSONWebKeys jsonWebKeys = vi.getJsonWebKeys();
                for (String kid : jsonWebKeys.keySet()) {
                    KERecord keRecord = getStore().create();
                    keRecord.fromJWK(jsonWebKeys.get(kid), kid.equals(jsonWebKeys.getDefaultKeyID()));
                    newRecords.put(keRecord.getIdentifier(), keRecord);
                    keysProcessed++;
                }
                visProcessed++;
                if (cleanupMigrated) {
                    vi.setJsonWebKeys(null);
                }
            }
            getStore().update(newRecords);
            say(" VIs processed : " + visProcessed);
            say("keys processed : " + keysProcessed);
            say("   VIs skipped : " + visSkipped);
            return;
        }
    }

    public static final String SET_NBF = "-nbf";
    public static final String SET_IAT = "-iat";
    public static final String SET_EXP = "-exp";

    public void set(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set " + SET_IAT + " | " + SET_NBF + " | " + SET_EXP + " index - set the iat, nbf, or exp fields");
            say("You may set these with ISO 8601 dates or integers (as seconds since epoch)");
            return;
        }
    }

    public static String CURRENT_EXP_FLAG = "-exp";
    public static String CURRENT_VALID_FLAG = "-valid";
    public static String CURRENT_SIGNING_KEYS = "-signing";

    public void get_current(InputLine inputLine) throws Throwable {
        int width = 8;
        if (showHelp(inputLine)) {
            say("get_current [" + LINE_LIST_COMMAND + "] [" + CURRENT_SIGNING_KEYS + "] [" + CURRENT_EXP_FLAG + " true | false] [" +
                    CURRENT_VALID_FLAG + " true | false] " + DEFAULT_SERVER_VI + " | index - get the current keys (valid or not) for a given VI");
            say("No argument means to list the keys for the default VI.");
            say(RJustify(LINE_LIST_COMMAND, width) + " - If present, use the line list (long form) rather than short.");
            say(RJustify(CURRENT_SIGNING_KEYS, width) + " - If present, return the signing keys the server wouldl use for the VI(s).");
            say(RJustify(CURRENT_EXP_FLAG, width) + " - if true, return only expired keys. If false, return un-expired.");
            say(getBlanks(width + +3) + "Omitting it returns all keys.");
            say(RJustify(CURRENT_VALID_FLAG, width) + " - If true (default), return only valid (nbf is before now) and if false ");
            say(getBlanks(width + 3) + "return nbf is after now. Omit means ignore valid date.");
            say("You can do all this with the search command, it is just a convenience.");
            say();
            say("E.g. Get the current signing keys, including those not yet valid, in the default VI");
            say("get_current -valid false -signing -vi default");
            say("typically, this is displayed on the well-known page for server keys.");
            say("E.g. get exactly what the server is using now to sign requests.");
            say("get_current  -signing -vi default");
            return;
        }

        VIStore viStore = getEnvironment().getVIStore();
        if ((!inputLine.hasArgs()) || inputLine.getLastArg().equals(DEFAULT_SERVER_VI)) {
            inputLine.setLastArg(SERVER_VI_ID.toString());
        }
        boolean lineList = inputLine.hasArg(LINE_LIST_COMMAND);
        inputLine.removeSwitch(LINE_LIST_COMMAND);
        boolean hasExpFlag = inputLine.hasArg(CURRENT_EXP_FLAG);
        boolean returnExpired = false;
        boolean hasValidFlag = inputLine.hasArg(CURRENT_VALID_FLAG);
        boolean returnValid = true;
        if (hasExpFlag) {
            returnExpired = inputLine.getBooleanNextArgFor(CURRENT_EXP_FLAG);
            inputLine.removeSwitchAndValue(CURRENT_EXP_FLAG);
        }
        if (hasValidFlag) {
            returnValid = inputLine.getBooleanNextArgFor(CURRENT_VALID_FLAG);
            inputLine.removeSwitchAndValue(CURRENT_VALID_FLAG);
        }
        boolean signingKeys = inputLine.hasArg(CURRENT_SIGNING_KEYS);
        inputLine.removeSwitch(CURRENT_SIGNING_KEYS);

        if(!inputLine.hasLastArg()){
            say("no vi specified.");
            return;
        }
        FoundIdentifiables foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
        if (foundIdentifiables == null || foundIdentifiables.isEmpty()) {
            say("VI not found");
            return;
        }
        int total = 0;
        for (Identifiable identifiable : foundIdentifiables) {
            VirtualIssuer vi = (VirtualIssuer) identifiable;
            IdentifiableMap<KERecord> map;
            int totalKeys = 0;

            if (signingKeys) {
                map = new IdentifiableMap<>();
                // aim is to get exactly what server signs with,
                JSONWebKeys jwks = getEnvironment().getJsonWebKeys(vi, true);
                for (String kid : jwks.keySet()) {
                    KERecord ker = getStore().getByKID(kid);
                    if (ker != null) {
                        map.put(ker);
                    }
                }
                if (map.isEmpty()) {
                    if (getEnvironment().isServerVI(vi)) {
                        map = jwksToIDMap(jwks);
                        totalKeys = map.size();
                    }else {
                        say("No signing keys found for VI " + vi.getIdentifierString());
                        return;
                    }
                }
            } else {
                map = getStore().getByVI(vi);
            }

            FoundIdentifiables foundIdentifiables1 = new FoundIdentifiables(false);
            // filter elements
            for (KERecord keRecord : map.values()) {
                if (!signingKeys) {
                    if (hasExpFlag) {
                        if (returnExpired) {
                            if (!keRecord.isExpired()) {
                                continue;
                            }
                        } else {
                            if (keRecord.isExpired()) {
                                continue;
                            }
                        }
                    }
                    if (hasValidFlag) {
                        if (returnValid) {
                            if (!keRecord.hasValidDate()) {
                                continue;
                            }
                        } else {
                            if (keRecord.hasValidDate()) {
                                continue;
                            }
                        }
                    }
                }
                foundIdentifiables1.add(keRecord);
            }
            //FoundIdentifiables foundIdentifiables1 = new FoundIdentifiables(false, map.values());
            if (lineList) {
                printLS(foundIdentifiables1, true, false, false);
            } else {
                printLS(foundIdentifiables1, false, false, true);
            }


            //end keys for
            say(totalKeys + " entries for " + vi.getIdentifierString());

        } // end VI for
        if (1 < foundIdentifiables.size()) {
            say("Total keys found over " + foundIdentifiables.size() + " VIs: " + total);
        }

    }

    public static String KR_ALL = "-all";
    public static String KR_KID = "-kid";
    public static String KR_VI = "-vi";
    public static String KR_CACHE_LIFETIME = "-cache";
    public static String KR_AT_LIFETIME = "-at";
    public static String KR_FORCE_FLAG = "-force";
    public static String KR_TEST_FLAG = "-test";

    protected void rotateHelp(InputLine inputLine) {
        String name = getMethodName(4);
        say(name + " [" + KR_ALL + " | " + KR_KID + " id | " + KR_VI + " vi " +
                KR_CACHE_LIFETIME + " cache_lifetime " +
                KR_AT_LIFETIME + " access_token_lifetime " +
                KR_TEST_FLAG + " " + KR_FORCE_FLAG + "]  [index] - rotate the key at the given index");
        say(RJustify(KR_ALL, 6) + " = rotate all keys in the store. If the " + KR_VI + " argument is present, this is ignored and only the speicifed VI is rotated.");
        say(RJustify(KR_KID, 6) + " = rotate the specific key by is key id.");
        say(RJustify(KR_VI, 6) + " = rotate the keys by for a given virtual issuer. A valid of default rotates the server keys.");
        say(RJustify(KR_CACHE_LIFETIME, 6) + " = set the cache lifetime grace perdiod. Default is 24 hours.");
        say(RJustify(KR_AT_LIFETIME, 6) + " = set the access token lifetime grace period. Default is the max server access token lifetime.");
        say(RJustify(KR_TEST_FLAG, 6) + " = (flag) test only, do not actually rotate the keys.");
        say(RJustify(KR_FORCE_FLAG, 6) + " = (flag) force the rotation, even if the key is not yet expired.");
        say("The index is the index (unique identifier or element in a result set) of the key in the store.");
        say("This will rotate the key(s) either per VI's policy or you may directly set the lifetimes");
        say("Setting at least one of " + KR_CACHE_LIFETIME + " or " + KR_AT_LIFETIME + " will override the policy");
        say("These accept lifetime in seconds (default) or with units, e.g. " + KR_AT_LIFETIME + " \"25 min\" (note the quotes!)");
        say("The scope of this is always the minimum, so specifying a kid and a vi will oinly process teh specific key for that kid.");
        say("\nNote that if you rotate a set of keys that are in the VI record, they will be automatically");
        say("migrated to the store since they require specific accounting information.");
        say("Once keys are in the store, for a VI, those are definitive, and supercede and other keys.");
        say("See also: get_rotation_configuration in the vi component.");
        say();
        say("E.g. Rotate every key in the store, using specific cache lifetime.");
        sayi(name + " " + KR_ALL + " " + KR_CACHE_LIFETIME + " \"2 days\"");
        say("E.g. Rotate the keys for a given VI.");
        sayi(name + " " + KR_VI + " oa4mp:/vi/1234567890");
        say("Note that this uses the policies of the VI and server.");
    }

    public void rotate(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            rotateHelp(inputLine);
            return;
        }
        if (!inputLine.hasArgs()) {
            say("no arguments provided");
            return;
        }
        if (getEnvironment().getKEStore() == null) {
            say("No key store enabled.");
            return;
        }
        boolean forceFlag = inputLine.hasArg(KR_FORCE_FLAG);
        inputLine.removeSwitch(KR_FORCE_FLAG);
        Long cacheLifetime = null;
        Long atLifetime = null;
        Identifier viID = null;
        boolean overrideKEC = false;
        boolean testOnly = inputLine.hasArg("-test");
        inputLine.removeSwitch("-test");
        if (inputLine.hasArg(KR_CACHE_LIFETIME)) {
            cacheLifetime = TimeUtil.getValueSecsOrMillis(inputLine.getNextArgFor(KR_CACHE_LIFETIME), true);
            inputLine.removeSwitchAndValue(KR_CACHE_LIFETIME);
            overrideKEC = true;
        }
        if (inputLine.hasArg(KR_AT_LIFETIME)) {
            atLifetime = TimeUtil.getValueSecsOrMillis(inputLine.getNextArgFor(KR_AT_LIFETIME), true);
            inputLine.removeSwitchAndValue(KR_AT_LIFETIME);
            overrideKEC = true;
        }

        boolean doKID = inputLine.hasArg(KR_KID);
        if (doKID) {
            String kid = inputLine.getNextArgFor(KR_KID);
            inputLine.removeSwitchAndValue(KR_KID);
            KERecord keRecord = getEnvironment().getKEStore().getByKID(kid);
            if (keRecord == null) {
                say("key with kid " + kid + " not found");
            } else {
                // get the policy.
                VirtualIssuer vi = (VirtualIssuer) getEnvironment().getVIStore().get(BasicIdentifier.newID(keRecord.getVi()));
                if (!overrideKEC) {
                    KEConfiguration keConfiguration = KEStoreUtilities.resolveKeConfiguration(getEnvironment(), vi);
                    if (!keConfiguration.enabled) {
                        return;
                    }
                    if (cacheLifetime == null) cacheLifetime = keConfiguration.cacheGracePeriod;
                    if (atLifetime == null) atLifetime = keConfiguration.atGracePeriod;
                }
                KERecord newRecord = KEStoreUtilities.rotate(getEnvironment().getKEStore(),
                        keRecord, cacheLifetime, atLifetime, testOnly);
                newRecord.setValid(true);
                if (testOnly) {
                    say("Test rotation of key with ID " + keRecord.getKid());
                    testBlurb(keRecord, cacheLifetime, atLifetime);
                } else {
                    getEnvironment().getKEStore().update(keRecord);
                    getEnvironment().getKEStore().save(newRecord);

                    say("rotated key, kid= " + newRecord.getKid());
                }
            }
            return;
        }

        boolean updateOldKeys = false;
        boolean doVI = inputLine.hasArg(KR_VI);
        if (doVI) {
            String viIDString = inputLine.getNextArgFor(KR_VI);
            inputLine.removeSwitchAndValue(KR_VI);
            if (viIDString.equals(DEFAULT_SERVER_VI)) {
                viID = SERVER_VI_ID;
            } else {
                viID = BasicIdentifier.newID(viIDString);
            }
            // try finding VIs
            VIStore viStore = getEnvironment().getVIStore();
            VirtualIssuer vi = (VirtualIssuer) viStore.get(viID);
            KEConfiguration viKEC;
            if(vi == null ){
                if(viIDString.equals(DEFAULT_SERVER_VI)) {
                    viKEC = getEnvironment().getKeConfiguration();
                }else{
                    say("No configuration for VI: " + viIDString);
                    return;
                }
            }else{
                 viKEC = KEStoreUtilities.resolveKeConfiguration(getEnvironment(), vi);
            }
            FoundIdentifiables foundVIs = findByIDOrRS(viStore, viID.toString());
            if((foundVIs == null || foundVIs.isEmpty()) && viIDString.equals(SERVER_VI_ID.toString())){
                foundVIs=new FoundIdentifiables(true);
                foundVIs.add(vi);
            }
            if (foundVIs == null || foundVIs.isEmpty()) {
                 if(viIDString.equals(DEFAULT_SERVER_VI)) {
                     foundVIs=new FoundIdentifiables(true);
                     if(vi == null){
                         // Case is that the default VI is only configured in the server config, there
                         // is no VI for it. Make a dummy for the rotation utility
                         foundVIs.add(new VirtualIssuer(SERVER_VI_ID));
                     }else{
                         foundVIs.add(vi);
                     }
                 }else{
                     say("No VI: " + viIDString);
                     return;
                 }
            }
                Map<Identifier, KERecord> map = KEStoreUtilities.rotate(getEnvironment(), foundVIs.getIdentifiers(),
                        viKEC, forceFlag, testOnly);
                if (map.size() == 0) {
                    DebugUtil.trace(this, "No keys found to rotate, KEC=" + viKEC);
                    say("No keys found for VI \"" + viIDString + "\". This utility only rotates valid keys that no not " +
                            "have an expiration date." +
                            "\nJust change that if you need to.");
                } else {
                    if (testOnly) {
                        int countLength = Integer.toString(map.size()).length();
                        List<Identifiable> keys = new ArrayList<>(map.values());
                        keys.addAll(map.values());
                        int[] fieldWidths = fieldWidths(keys);
                        say("Testing found  " + map.size() + " keys to rotate. No keys altered or added.");
                        String header = columnHeader(countLength, fieldWidths);
                        if (0 < map.size() && !isTrivial(header)) {
                            say(header);
                        }
                        for (Identifier id : map.keySet()) {
                            KERecord keRecord = map.get(id);
                            say(StringUtils.getBlanks(countLength + 2) + format(keRecord, countLength, fieldWidths));
                            //say(keRecord.getKid() + " | " + keRecord.getAlg() + " | exp = " +")");
                        }
                        testBlurb(null, viKEC.cacheGracePeriod, viKEC.atGracePeriod);
                    } else {
                        say("rotated " + map.size() + " keys");
                    }
                }
                return;

        } //end if VI

        boolean doAll = inputLine.hasArg(KR_ALL);
        inputLine.removeSwitch(KR_ALL);
        if (doAll) {
            // process every element in the store. This is a major update and should be done with caution.
            getStore().getCurrentKeys();
            //  KEStoreUtilities.rotate(getStore(),null, cacheLifetime, atLifetime);
        }
        // Default case, Standard IDs for KE records possibly in a result set.
        FoundIdentifiables foundIdentifiables = findByIDOrRS(getStore(), inputLine.getLastArg()); // See if they are getting KErecords
        if (foundIdentifiables != null && !foundIdentifiables.isEmpty()) {

            // there are found identifiables in the key store. Float to the right types.
            Map<Identifier, KERecord> keRecords = new HashMap<>(foundIdentifiables.size());
            for (Identifiable identifiable : foundIdentifiables) {
                KERecord keRecord = (KERecord) identifiable;
                keRecords.put(keRecord.getIdentifier(), keRecord);
            }
            Map<Identifier, KERecord> newRecords = KEStoreUtilities.rotate(getStore(), keRecords, forceFlag, cacheLifetime, atLifetime, true, testOnly);
            if (testOnly) {
                for (Identifier id : newRecords.keySet()) {
                    KERecord keRecord = newRecords.get(id);
                    say(format(keRecord));
                }
                say("tested and found " + newRecords.size() + " keys to rotate:");
                testBlurb(null, cacheLifetime, atLifetime);
            } else {
                say("rotated " + newRecords.size() + " keys");
            }
            return;
        }
   say("no keys found.");
    }

    protected void testBlurb(KERecord keRecord, long cache, long at) {
        if (keRecord != null) {
            say("key exp : " + Iso8601.date2String(keRecord.getExp()));
            say("key nbf : " + Iso8601.date2String(keRecord.getNbf()));
        }
        say("cache lifetime : " + cache + " ms.");
        say("   at lifetime : " + at + " ms.");
        say("  current time : " + Iso8601.date2String(new Date()));
    }

    public static String CREATE_KEYS_CURVE = "-curve";
    public static String CREATE_KEYS_TYPE = "-type";
    public static String CREATE_KEYS_SIZE = "-size";
    public static int CREATE_KEYS_DEFAULT_SIZE = 4096;

    public void create_keys(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("create_keys [" + CREATE_KEYS_TYPE + " RSA | EC] [" + CREATE_KEYS_CURVE + " curve] [" + CREATE_KEYS_SIZE + " size] [vi] - create a set of keys for the given curve. No arguments defaults to RSA.");
            say("Note that this just creates the keys. It does not set them active, valid or set anything other than");
            say("the issues at date.");
            say("The default is RSA curves with a key size of " + CREATE_KEYS_DEFAULT_SIZE + " bits.");
            say("Supported EC curves are P-256 |  P-384 | P-521");
            say("If the vi argument is given, the keys will be created for the given VI. No VI or");
            say("A VI of " + SERVER_VI_ID + " means to create the keys for the server.");
            say("It also supports creating a result set for the new keys with the -rs flag.");
            return;
        }
        String type = "RSA", curve = null;
        int size = CREATE_KEYS_DEFAULT_SIZE;
        JSONWebKeys jsonWebKeys = null;
        if (inputLine.hasArg(CREATE_KEYS_TYPE)) {
            type = inputLine.getNextArgFor(CREATE_KEYS_TYPE);
            inputLine.removeSwitchAndValue(CREATE_KEYS_TYPE);
        }
        JWKUtil2 jwkUtil2 = new JWKUtil2();
        String defaultID = jwkUtil2.createID();
        if (type.equalsIgnoreCase("RSA")) {
            try {
                if (inputLine.hasArg(CREATE_KEYS_SIZE)) {
                    size = inputLine.getIntNextArg(CREATE_KEYS_SIZE);
                    inputLine.removeSwitchAndValue(CREATE_KEYS_SIZE);
                }
                jsonWebKeys = SigningCommands.createRSAJsonWebKeys(size, defaultID);
            } catch (ArgumentNotFoundException anfx) {
                say("size argument must be an integer:" + anfx.getMessage());
                return;
            }
        }
        if (type.equalsIgnoreCase("EC")) {
            if (inputLine.hasArg(CREATE_KEYS_CURVE)) {
                curve = inputLine.getNextArgFor(CREATE_KEYS_CURVE);
                inputLine.removeSwitchAndValue(CREATE_KEYS_CURVE);
                jsonWebKeys = SigningCommands.createECJsonWebKeys(curve, defaultID); // Dummy default key id.
            } else {
                jsonWebKeys = SigningCommands.createECJsonWebKeys(defaultID); // Dummy default key id.
            }
        }
        boolean hasRS = inputLine.hasArg(RESULT_SET_KEY);
        String rsName = null;
        if (hasRS) {

            rsName = inputLine.getNextArgFor(RESULT_SET_KEY);
            inputLine.removeSwitchAndValue(RESULT_SET_KEY);
        }
        URI vi = null;
        if (inputLine.hasArgs()) {
            try {
                vi = URI.create(inputLine.getLastArg());
            } catch (Throwable ex) {
                say("unable to parse VI as a URI: " + ex.getMessage());
                return;
            }
            VirtualIssuer virtualIssuer = (VirtualIssuer) getEnvironment().getVIStore().get(BasicIdentifier.newID(vi));
            if (virtualIssuer == null) {
                if (!"y".equals(readline("warning virtual issuer \"" + vi + "\" not found. Proceed? (y/n)"))) {
                    say("aborting");
                    return;
                }
            }
        } else {
            vi = SERVER_VI_ID.getUri();
        }

        if (jsonWebKeys == null) {
            say("Unsupported key type \"" + type + "\"");
            return;
        }
        // now we can create the records etc. to go with this.
        Map<Identifier, KERecord> newRecords = new HashMap<>();
        List<Identifiable> hackyList = new ArrayList<>();
        List<String> keyIds = new ArrayList<>();
        for (String kid : jsonWebKeys.keySet()) {
            KERecord keRecord = getStore().create();
            keRecord.setVi(vi);
            keRecord.fromJWK(jsonWebKeys.get(kid), false);
            hackyList.add(keRecord);
            newRecords.put(keRecord.getIdentifier(), keRecord);
            keyIds.add(keRecord.getKid());
        }
        getStore().putAll(newRecords);
        if (hasRS) {
            RSRecord rsRecord = new RSRecord(hackyList, getKeys().allKeys());
            getResultSets().put(rsName, rsRecord);
        }
        say("Added " + keyIds.size() + " keys to the store. Key ids:");
        for (String kid : keyIds) {
            say(kid);
        }
    }

    protected void showHelp() {
        String name = getMethodName(3);
        say(name + " [vi_id | default] - show the signing keys for the given VI. No ID means show the server signing keys.");
        say("You may also supply the word \"default\" to show the keys for the server (in the default VI).");
        say("This will find them wherever they are and tell you where it found them.");
        say("Note that the default for the set will have an * next to its key id, e.g. *BD9327856EF");
        say("This is different than the ls command, since the ls command will show what is in the key store.");
        say("If there is no key store (e.g., the keys are in the server config), this will show the keys in the server config.");
    }

    public void show(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showHelp();
            return;
        }

        boolean defaultID = false;
        if (inputLine.hasLastArg()) {
            defaultID = inputLine.getLastArg().equals(SERVER_VI_ID.toString());
            if (inputLine.getLastArg().equals(DEFAULT_SERVER_VI)) {
                inputLine.setLastArg(SERVER_VI_ID.toString());
                defaultID = true;
            }
        } else {
            inputLine.setLastArg(SERVER_VI_ID.toString());
            defaultID = true;
        }
        JSONWebKeys jwks = null;
        VIStore viStore = getEnvironment().getVIStore();
        Identifier viID = BasicIdentifier.newID(inputLine.getLastArg());
        VirtualIssuer vi = (VirtualIssuer) viStore.get(viID);
        String location = "";
        IdentifiableMap<KERecord> map = null;

        // Eight cases to unscramble.
        if (getEnvironment().hasKEStore()) {
            if (vi == null) {
                if (defaultID) {
                    location = "keys in the store";
                    map = getStore().getByVI(new VirtualIssuer(SERVER_VI_ID));
                    if (map.isEmpty()) {
                        location = "keys are in the server configuration";
                        jwks = getEnvironment().getJsonWebKeys(); // Form teh server config, has default key set.
                        map = jwksToIDMap(jwks);
                    }
                } else {
                    // has keys store, no vi and is not the default
                    location = "keys in the issuer";
                    map = getStore().getByVI(new VirtualIssuer(viID)); // dummy VI
                    // It is possible to create (e.g. test) keys in the store with no
                    // VI *or* being trying to track down orphans after deleting a VI.
                } // end if has default ID
            } else {
                if (defaultID) {
                    // has key store, has VI, is the default
                    location = "keys in the store";
                    map = getStore().getByVI(new VirtualIssuer(SERVER_VI_ID)); // dummy VI
                    if (map.isEmpty()) {
                        jwks = vi.getJsonWebKeys();
                        location = "keys in the VI";
                        if (jwks.isEmpty()) {
                            location = "keys are in the server configuration";
                            jwks = getEnvironment().getJsonWebKeys(); // From the server config, has default key set.
                        }
                        map = jwksToIDMap(jwks);
                    }
                } else {
                    // has key store, has VI, not default
                    location = "keys in the store";
                    // no VI, so *maybe* they are requesting keys in the store that do not
                    // have one. This can happen if a VI is deleted and its keys are still
                    // stored. This lets the user find orphans.
                    map = getStore().getByVI(new VirtualIssuer(viID));
                    if (map.isEmpty()) {
                        say("no keys found for virtual issuer \"" + viID + "\"");
                        return;
                    }
                } // end if has default ID
            } // end if for vi null
        } else {
            if (vi == null) {
                if (defaultID) {
                    // no store, no vi, is default can only be in the server.
                    location = "keys are in the server configuration";
                    jwks = getEnvironment().getJsonWebKeys(); // Form teh server config, has default key set.
                    map = jwksToIDMap(jwks);
                } else {
                    // no store, no VI, not default
                    // can't happen. ?? Throw exception?
                } // end if has default ID
            } else {
                if (defaultID) {
                    // no store, has VI, is default
                    location = "keys in the issuer";
                    jwks = vi.getJsonWebKeys();
                    if (jwks == null || jwks.isEmpty()) {
                        jwks = getEnvironment().getJsonWebKeys();
                        location = "keys in the server configuration";
                    }
                    map = jwksToIDMap(jwks);
                } else {
                    // no store, has VI, not default
                    jwks = vi.getJsonWebKeys();
                    jwks.setDefaultKeyID(vi.getDefaultKeyID());
                    location = "keys in the VI";
                    map = jwksToIDMap(jwks);
                } // end if has default ID
            } // end if for vi null
        } //end conditional for having a store


        // Now we have a general VI and need to get its keys. These are either in the
        if ((jwks == null || jwks.isEmpty()) && map == null) {
            say("no keys found.");
            return;
        } else {
            FoundIdentifiables foundIdentifiables = new FoundIdentifiables(false);
            foundIdentifiables.addAll(map.values());
            printLS(foundIdentifiables, false, false, true);
        }
        say(location);

    }


    /**
     * Converts a set of JSONWeb keys to a map of KERecords. This is used for a variety of purposes,
     * including rotating server keys that only reside in the configuration file.
     *
     * @param jwks
     * @param defaultID
     * @param viID
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static Map<Identifier, KERecord> getIdentifierKERecordMap(JSONWebKeys jwks, boolean defaultID, URI viID) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Map<Identifier, KERecord> map;
        map = new HashMap<>();
        for (String kid : jwks.keySet()) {
            JSONWebKey webKey = jwks.get(kid);
            KERecord keRecord = new KERecord(BasicIdentifier.randomID());
            keRecord.fromJWK(webKey, jwks.getDefaultKeyID().equals(kid));
            if (defaultID) {
                keRecord.setVi(SERVER_VI_ID.getUri());
            } else {
                keRecord.setVi(viID);
            }
            keRecord.setValid(true);
            keRecord.setDefault(jwks.getDefaultKeyID().equals(kid));
            map.put(keRecord.getIdentifier(), keRecord);
        }
        return map;
    }

    public static final String KEY_ROTATION_SYSTEM_CFG = "system";

    public void policy(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            String name = getMethodName(2);
            say(name + " [" + KEY_ROTATION_SYSTEM_CFG + "] | [" + DEFAULT_SERVER_VI + "] vi - get the current key rotation configuration for the VI.");
            say(RJustify(KEY_ROTATION_SYSTEM_CFG,10) + " = the system's rotation configuration.");
            say(RJustify(DEFAULT_SERVER_VI,10) + " = the rotation configuration for the default virtual issuer.");
            say("or supply the id of a virtual issuer to get its configuration.");
            say("No argument means to show whatever the system is using for its configuration, regardless of its origin.");
            say();
            rotationDefaults();
            return;
        }
        if(!inputLine.hasArgs()){
            formatKEC(getEnvironment().getKeConfiguration());
             return;
        }
        if (inputLine.hasArg(KEY_ROTATION_SYSTEM_CFG)) {
            if(getEnvironment().getKeConfiguration().isInConfigFile){
                formatKEC(getEnvironment().getKeConfiguration());
                say("Configuration explicitly given in server configuration file.");
            }else{
                say("Not configured in the server configuration file.");
            }
            return;
        }
        if (inputLine.hasArg(DEFAULT_SERVER_VI) || inputLine.hasArg(OA2SE.SERVER_VI_ID.toString())) {
            VirtualIssuer vi = (VirtualIssuer) getEnvironment().getVIStore().get(OA2SE.SERVER_VI_ID);
            if (vi == null) {
                say("No default virtual issuer found.");
            } else {
                formatKEC(vi);
            }
            return;
        }

        FoundIdentifiables identifiables = findItem(getEnvironment().getVIStore(), inputLine, false);
        if (identifiables == null || identifiables.isEmpty()) {
            say("sorry, no such virtual issuer \"" + inputLine.getLastArg() + "\"");
            return;
        }
        VirtualIssuer vi = (VirtualIssuer) identifiables.get(0);
        formatKEC(vi);
    }

    protected void rotationDefaults() {
        int width = 11;

        say("The following are the default values for key rotation:");
        say(RJustify(Long.toString(GRACE_PERIOD_NOT_CONFIGURED), width) + " = grace period not configured");
        say(RJustify(MAX_ACCESS_TOKEN_LIFETIME_DEFAULT + " ms", width) + " = max access token lifetime");
        say(RJustify((24 * 3600 * 1000L) + " ms", width) + " = 24 hours (suggested cache grace period)");
    }
    protected void formatKEC(KEConfiguration keConfiguration) {
        int width = 35;
        VISerializationKeys vik = new VISerializationKeys();
        say(RJustify(vik.keyRotationCacheGracePeriod(), width) + " = " + keConfiguration.cacheGracePeriod + " ms");
        say(RJustify(vik.keyRotationATGracePeriod(), width) + " = " + keConfiguration.atGracePeriod + " ms");
        say(RJustify(vik.keyRotationEnabled(), width) + " = " + keConfiguration.enabled);
        say(RJustify("allow overrides", width) + " = " + keConfiguration.allowOverride);
        if (!keConfiguration.isConfgured() && !keConfiguration.allowOverride ) {
            say( " *** not configured ***");
        }
    }

    protected void formatKEC(VirtualIssuer vi) {
        if (!vi.hasKeyRotationConfiguration()) {
            say( "key rotation not configured");
        }
        formatKEC(vi.getKeyRotationConfiguration());
    }
    @Override
    public void ls(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            super.ls(inputLine);
            say("You may also specify the following switches.");
            say(RJustify(KR_VI, 6) + " = specify a specific VI to get all the keys for.");
            say("Compare with get_current which will give a summary of the keys for a given");
            say("VI, not just listing the key store records.");
            say(RJustify(KR_KID, 6) + " = specify a specific key id to get the key record.");
            return;
        }
        if (getEnvironment().getKEStore() == null) {
            say("No key store enabled. You may still call \"show\" to see the signing keys for various VIs.");
            return;
        }
        FoundIdentifiables foundIdentifiables = null;
        IdentifiableMap<KERecord> map = null;
        boolean gotOne = false;
        if (inputLine.hasArg(KR_KID)) {
            String kid = inputLine.getNextArgFor(KR_KID);
            inputLine.removeSwitchAndValue(KR_KID);
            KERecord keRecord = getStore().getByKID(kid);
            if (keRecord == null) {
                say("no entry found with kid \"" + kid + "\"");
                return;
            }
            map = new IdentifiableMap<>();
            map.put(keRecord);
            gotOne = true;
        }
        if (inputLine.hasArg(KR_VI) && !gotOne) {
            String vi = inputLine.getNextArgFor(KR_VI);
            inputLine.removeSwitchAndValue(KR_VI);
            if (vi.equals(DEFAULT_SERVER_VI)) {
                vi = SERVER_VI_ID.toString();
            }
            VirtualIssuer virtualIssuer = (VirtualIssuer) getEnvironment().getVIStore().get(BasicIdentifier.newID(vi));
            if (virtualIssuer == null) {
                virtualIssuer = new VirtualIssuer(BasicIdentifier.newID(vi));
            }

            map = getStore().getByVI(virtualIssuer);
            if (map == null || map.isEmpty()) {
                say("no entries for VI \"" + vi + "\"");
                return;
            }
            gotOne = true;
        }
        if (gotOne) {
            boolean listSingleLines = inputLine.hasArg(LINE_LIST_COMMAND);
            boolean listMultiLines = inputLine.hasArg(VERBOSE_COMMAND);
            boolean shortForm = !(listMultiLines || listSingleLines);
            if ((listSingleLines && listMultiLines)) {
                say("inconsistent flags. You cannot have both single and multiline output at the same time.");
                return;
            }
            foundIdentifiables = new FoundIdentifiables(false, map.values());

            printLS(foundIdentifiables, listSingleLines, listMultiLines, shortForm);
            return;

        }
        super.ls(inputLine);
    }

    public void set_default(InputLine inputLine) {
        if (showHelp(inputLine)) {
            say("set_default old_kid new_kid - change the default flag on the old_kid");
            say("and new_kid so new_kid is the default.");
            say("Note this uses kids (key ids) rather than identifiers to make sure you");
            say("explicitly set what you want. This way a default is not accidentally reset.");
            return;
        }
        if (inputLine.getArgCount() != 2) {
            say("Missing argument. Must have an old and new kid.");
            return;
        }
        String oldKID = inputLine.getArg(1);
        String newKID = inputLine.getArg(2);
        KERecord oldKER = getStore().getByKID(oldKID);
        if (oldKER == null) {
            say("Old record for KID \"" + oldKID + "\" not found, aborting.");
            return;
        }
        KERecord newKER = getStore().getByKID(newKID);
        if (newKER == null) {
            say("New record for KID \"" + newKID + "\" not found, aborting.");
            return;
        }
        IdentifiableMap<KERecord> updateMap = new IdentifiableMap<>();
        if (oldKER.getDefault()) {
            oldKER.setDefault(false);
            updateMap.put(oldKER);
        } else {
            say("Warning, old key with kid \"" + oldKID + "\" was not a current default.");
        }
        if (newKER.getDefault()) {
            say("Warning, new key with kid \"" + newKID + "\" was already the current default.");
        } else {
            if (newKER.isExpired()) {
                say("Warning, the new key is expired.");
                try {
                    if ("y".equalsIgnoreCase(getInput("Abort?", "y"))) {
                        say("aborting...");
                        return;
                    }
                } catch (IOException e) {
                    throw new NFWException(e);
                    // Have to have an exception here, but they can't get here unless I/O is
                    // working...
                }
            }
            newKER.setDefault(true);
            updateMap.put(newKER);
        }
        getStore().update(updateMap);
        say("done!");
    }

    @Override
    protected Identifiable preCreation(Identifiable identifiable, int magicNumber) {
        KERecord kerecord = (KERecord) super.preCreation(identifiable, magicNumber);

        JWKUtil2 jwkUtil2 = new JWKUtil2();
        try {
            JSONWebKey jwk = jwkUtil2.createRSAKey();
            kerecord.fromJWK(jwk, false);
            Date now = new Date();
            kerecord.setLastModifiedTS(now);
            kerecord.setCreationTS(now);
            kerecord.setLastAccessed(now);
            kerecord.setVi(SERVER_VI_ID.getUri());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return kerecord;
    }

    @Override
    protected Identifiable preCopy(Identifiable x) {
        KERecord kerecord = (KERecord) super.preCopy(x);
        // Since a constraint on the store is that the KID
        // is unique, we set it to something random here.
        JWKUtil2 jwkUtil2 = new JWKUtil2();
        kerecord.setKid(jwkUtil2.createID());
        Date now = new Date();
        kerecord.setLastAccessed(now);
        kerecord.setCreationTS(now);
        kerecord.setLastModifiedTS(now);
        return kerecord;
    }

    @Override
    protected void showCreateHelp() {
        super.showCreateHelp();
        say("Note that for a generic key, a default RSA key is created. You can just resetrun the");
        ;
        say("this from the command line, e.g. from a file.");
    }

    @Override
    protected void showCopyHelp() {
        super.showCopyHelp();
        say("Note that this generates a random kid (key id) for the new record.");
        say("This is because all kids in the store must be unique. Reset it if you choose.");
    }

}


