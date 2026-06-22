package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableMap;
import edu.uiuc.ncsa.security.core.util.Iso8601;
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
import org.oa4mp.server.loader.oauth2.storage.vi.VIStore;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.oa4mp.server.loader.qdl.util.SigningCommands;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

import static edu.uiuc.ncsa.security.core.util.StringUtils.*;

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
        KERecord keRecord = (KERecord) identifiable;
        int width = 25; // long width, for ISO dates e.g.
        int s = 5; // short width
        String out = LJustify((keRecord.getDefault() ? "*" : "") + keRecord.getKid(), 35) +
                " " + LJustify(keRecord.getAlg(), s) +
                " " + LJustify(keRecord.getUse(), s) +
                " " + (keRecord.getValid() ? "true " : "false") + // make length match
                //      " " + center((keRecord.getNbf() == null?"--": Iso8601.date2String(keRecord.getNbf())),width) +
                " " + center((keRecord.getExp() == null ? "--" : Iso8601.date2String(keRecord.getExp())), width) +
                " " + LJustify(keRecord.getVi().toString(), 35) +
                " " + keRecord.getIdentifierString();
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
                // reords based on the identifier. We, however, need to check if the key is already in the store
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
        say("migrate [" + MIGRATE_LIST + "] | [" + MIGRATE_CLEANUP + "] | [" +
                MIGRATE_ALL_VIS + " | vi_id][" + MIGRATE_SERVER_KEYS + "] -  migrate the keys stored in a VI to ");

        say("this store. Optionally remove them from the VI. Once migrated,");
        say("the system manages them and the keys stored in the VI are ignoared");
        say(RJustify(MIGRATE_SERVER_KEYS, width) + " = Migrate the keys in the server configuration to the store. This cannot be combined with other flags.");
        say(RJustify(MIGRATE_LIST, width) + " = return a list of VIs that have stored keys.");
        say(RJustify("vi_id", width) + " = migrate the keys stored in the given VI only.");
        say(RJustify(MIGRATE_ALL_VIS, width) + " = migrate all VI keys to this store.");
        say(RJustify(MIGRATE_CLEANUP, width) + " = remove the keys stored in a VI.");
        say("This does allow for result sets as well for migration.");
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

        VIStore<VirtualIssuer> viStore = getEnvironment().getVIStore();

        if (migrateServerKeys) {
            VirtualIssuer vi = viStore.get(OA2SE.SERVER_VI_ID);
            // if the default VI for the server does not exist, create it.
            if (vi == null) {
                vi = viStore.create();
                vi.setIdentifier(OA2SE.SERVER_VI_ID);
                vi.setValid(true);
                vi.setDescription("Dafault OA4MP Server Configuration");
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
                    for(String kid : getEnvironment().getServerJWKS().keySet()){
                        JSONWebKey webKey = getEnvironment().getServerJWKS().get(kid);
                        map.put(KEStoreUtilities.createSingleKERecord(getStore(),
                                OA2SE.SERVER_VI_ID.getUri(), true, webKey, getEnvironment().getServerJWKS().getDefaultKeyID()));
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
        FoundIdentifiables foundIdentifiables = null;
        if (migrateAll) {
            migrate(null, cleanupMigrated);
        } else {
            if (inputLine.hasArgs()) {
                foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
            }
            migrate(foundIdentifiables, cleanupMigrated);
        }
        Map<Identifier, KERecord> newRecords = new HashMap<>();
        // case 1, do explicitly requested migration
        if (foundIdentifiables != null && !foundIdentifiables.isEmpty()) {
            int keysProcessed = 0;
            int visProcessed = 0;
            int visSkipped = 0;
            for (Identifiable identifiable : foundIdentifiables) {
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

    public void get_current(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("get_current " + DEFAULT_SERVER_VI + " | index - get the current values for the given key");
            return;
        }
        VIStore viStore = getEnvironment().getVIStore();
        if (!inputLine.hasArgs()) {
            say("no arguments provided");
            return;
        }
        if (inputLine.getLastArg().equals(DEFAULT_SERVER_VI)) {
            inputLine.setLastArg(OA2SE.SERVER_VI_ID.toString());
        }
        FoundIdentifiables foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
        if (foundIdentifiables == null || foundIdentifiables.isEmpty()) {
            say("VI not found");
            return;
        }
        for (Identifiable identifiable : foundIdentifiables) {
            VirtualIssuer vi = (VirtualIssuer) identifiable;
            say(getStore().getCurrentKeys(vi).toString());
        }

    }

    public static String KR_ALL = "-all";
    public static String KR_KID = "-kid";
    public static String KR_VI = "-vi";
    public static String KR_CACHE_LIFETIME = "-cache";
    public static String KR_AT_LIFETIME = "-at";

    protected void rotateHelp(InputLine inputLine) {
        say("rotate [" + KR_ALL + " | " + KR_KID + " id | " + KR_VI + " vi " +
                KR_CACHE_LIFETIME + " cache_lifetime " +
                KR_AT_LIFETIME + " access_token_lifetime | index] - rotate the key at the given index");
        say(KR_ALL + " = rotate all keys in the store. If the " + KR_VI + " argument is present, this is ignored and only the speicifed VI is rotated.");
        say(KR_KID + " = rotate the specific key by is key id.");
        say(KR_VI + " = rotate the keys by for a given virtual issuer. A valid of default rotates the server keys.");
        say(KR_CACHE_LIFETIME + " = set the cache lifetime grace perdiod. Default is 24 hours.");
        say(KR_AT_LIFETIME + " = set the access token lifetime grace period. Default is the max server access token lifetime.");
        say("The index is the index (unique identifier or element in a result set) of the key in the store.");
        say("This will rotate the key(s) either per VI's policy or you may directly set the lifetimes");
        say("Setting at least one of " + KR_CACHE_LIFETIME + " or " + KR_AT_LIFETIME + " will override the policy");
        say("These accept lifetime in seconds (default) or with units, e.g. " + KR_AT_LIFETIME + " \"25 min\" (note the quotes!)");
        say("The scope of this is always the minimum, so specifying a kid and a vi will oinly process teh specific key for that kid.");
        say();
        say("E.g. Rotate every key in the store, using specific cache lifetime.");
        sayi("  rotate " + KR_ALL + " " + KR_CACHE_LIFETIME + " \"2 days\"");
        say("E.g. Rotate the keys for a given VI.");
        sayi("  rotate " + KR_VI + " oa4mp:/vi/1234567890");
        say("Note that this uses the policies of the VI and server.");
        ;
    }

    public void rotate(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            rotateHelp(inputLine);
            return;
        }
        if(!inputLine.hasArgs()){
            say("no artguments provided");
            return;
        }
        if (getEnvironment().getKEStore() == null) {
            say("No key store enabled.");
            return;
        }
        Long cacheLifetime = null;
        Long atLifetime = null;
        Identifier viID = null;
        boolean overrideKEC = false;

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
        KEConfiguration serverKEC;
        VirtualIssuer serverVI = (VirtualIssuer) getEnvironment().getVIStore().get(OA2SE.SERVER_VI_ID);
        if (serverVI == null) {
            serverKEC = getEnvironment().getKeConfiguration();
            if (cacheLifetime != null) serverKEC.cacheGracePeriod = cacheLifetime;
            if (atLifetime != null) serverKEC.atGracePeriod = atLifetime;
            if (!serverKEC.isConfgured()) {
                say("No ration configuration found.");
                return;
            }
        } else {
            serverKEC = KEStoreUtilities.resolveKeConfiguration(getEnvironment(), serverVI);
            if (cacheLifetime == null) cacheLifetime = serverKEC.cacheGracePeriod;
            if (atLifetime == null) atLifetime = serverKEC.atGracePeriod;
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
                KERecord newRecord = KEStoreUtilities.rotate(getEnvironment().getKEStore(), keRecord, cacheLifetime, atLifetime);
                newRecord.setValid(true);
                getEnvironment().getKEStore().update(keRecord);
                getEnvironment().getKEStore().save(newRecord);
                say("rotated key, kid= " + newRecord.getKid());
            }
            return;
        }

        boolean doVI = inputLine.hasArg(KR_VI);
        if (doVI) {
            String viIDString = inputLine.getNextArgFor(KR_VI);
            inputLine.removeSwitchAndValue(KR_VI);
            if (viIDString.equals(DEFAULT_SERVER_VI)) {
                viID = OA2SE.SERVER_VI_ID;
            } else {
                viID = BasicIdentifier.newID(viIDString);
            }
            // try finding VIs
            VIStore viStore = getEnvironment().getVIStore();
            FoundIdentifiables foundIdentifiables = findByIDOrRS(viStore, viID.toString());
            if (foundIdentifiables != null && !foundIdentifiables.isEmpty()) {
                KEStoreUtilities.rotate(getEnvironment(), foundIdentifiables.getIdentifiers(), serverKEC,false);
                return;
            } // Last ditch effort -- find in server config.
            if (viID.equals(OA2SE.SERVER_VI_ID)) {
                // edge ccase is that they have not made a virtual issuer for the default
                // but have rotate keys.
                VirtualIssuer vi = new VirtualIssuer(viID);

                Map<Identifier, KERecord> serverKERs = getStore().getByVI(vi); // it is *possible* that there is no VI if it's the default.
                if (serverKERs != null && !serverKERs.isEmpty()) {
                    serverKERs = KEStoreUtilities.rotate(getStore(), serverKERs, serverKEC.cacheGracePeriod, serverKEC.atGracePeriod, true);
                    say("Rotated " + serverKERs.size() + " keys");
                    return;
                }
                JSONWebKeys keys = getEnvironment().getServerJWKS();
                if (keys == null || keys.isEmpty()) {
                    say("No keys found, cannot rotate");
                    return;
                }
                Map<Identifier, KERecord> map = getIdentifierKERecordMap(keys, true, null);
                map = KEStoreUtilities.rotate(getStore(), map, serverKEC.cacheGracePeriod, serverKEC.atGracePeriod, false);
                say("Rotated " + serverKERs.size() + " keys");
            }else{
                say("VI \"" + viIDString + "\" not found");
            }
            return;
        }

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
            Map<Identifier, KERecord> newRecords = KEStoreUtilities.rotate(getStore(), keRecords, cacheLifetime, atLifetime, true);
            say("rotated " + newRecords.size() + " keys");
            return;
        }

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
            say("A VI of " + OA2SE.SERVER_VI_ID + " means to create the keys for the server.");
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
            vi = OA2SE.SERVER_VI_ID.getUri();
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
        say("show [vi_id | default] - show the signing keys for the given VI. No ID means show the server signing keys.");
        say("You may also supply the word \"default\" to show the keys for the server (in the default VI).");
        say("This will find them wherever they are and tell you where it found them.");
        say("Note that the default for the set will have an * next to its key id, e.g. *BD9327856EF");
    }

    public void show(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showHelp();
            return;
        }
        boolean defaultID = false;
        if (inputLine.hasLastArg()) {
            defaultID = inputLine.getLastArg().equals(OA2SE.SERVER_VI_ID.toString());
            if (inputLine.getLastArg().equals(DEFAULT_SERVER_VI)) {
                inputLine.setLastArg(OA2SE.SERVER_VI_ID.toString());
                defaultID = true;
            }
        } else {
            inputLine.setLastArg(OA2SE.SERVER_VI_ID.toString());
            defaultID = true;
        }
        JSONWebKeys jwks = null;
        VIStore viStore = getEnvironment().getVIStore();
        VirtualIssuer vi = (VirtualIssuer) viStore.get(BasicIdentifier.newID(inputLine.getLastArg()));
        String location = "";
        Map<Identifier, KERecord> map = null;
        if (getEnvironment().getKEStore() == null || (defaultID && vi == null)) { // handles case default keys not in store
            if (vi == null) {
                if (defaultID) {
                    location = "Keys are in the system configuration file.";
                    jwks = getEnvironment().getServerJWKS();
                }
            } else {
                location = "keys are in the VI record";
                jwks = vi.getJsonWebKeys();
                if (!jwks.hasDefaultKey()) {
                    jwks.setDefaultKeyID(vi.getDefaultKeyID());
                }
            }
            // create dummy map for formatting. This creates it from the VI.
            map = getIdentifierKERecordMap(jwks, defaultID, OA2SE.SERVER_VI_ID.getUri());
        } else {
            map = getStore().getByVI(vi);
            location = "keys are in the key store";
            if (map == null || map.isEmpty()) {
                // edge case -- no keys in VI, but only server keys in Environemnt.
                if (defaultID) {
                    location = "keys are in the system configuration file.";
                    jwks = getEnvironment().getServerJWKS();
                    map = new HashMap<>();
                    for (JSONWebKey webKey : jwks.values()) {
                        KERecord keRecord = KEStoreUtilities.createSingleKERecord(getStore(), OA2SE.SERVER_VI_ID.getUri(), true, webKey, jwks.getDefaultKeyID());
                        map.put(keRecord.getIdentifier(), keRecord );
                    }
                }
            }
        }
        // Now we have a general VI and need to get its keys. These are either in the
        if ((jwks == null || jwks.isEmpty()) && map == null) {
            say("no keys found.");
            return;
        } else {
            for (Identifier id : map.keySet()) {
                KERecord keRecord = map.get(id);
                say(format(keRecord));
            }
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
                keRecord.setVi(OA2SE.SERVER_VI_ID.getUri());
            } else {
                keRecord.setVi(viID);
            }
            keRecord.setValid(true);
            keRecord.setDefault(jwks.getDefaultKeyID().equals(kid));
            map.put(keRecord.getIdentifier(), keRecord);
        }
        return map;
    }

    public void policy(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("policy [vi] - get the key rotation policy for the given VI. No argument means default.");
            say("policy - get the policy for the server");
            return;
        }
        VIStore viStore = getEnvironment().getVIStore();
        if (inputLine.hasArgs()) {
            String vi = inputLine.getLastArg();
            VirtualIssuer virtualIssuer;
            if (vi.equals(DEFAULT_SERVER_VI) || vi.equals(OA2SE.SERVER_VI_ID.toString())) {
                virtualIssuer = (VirtualIssuer) viStore.get(OA2SE.SERVER_VI_ID);
                if (virtualIssuer == null) {
                    say("no default VI");
                    return;
                }
            }
            virtualIssuer = (VirtualIssuer) viStore.get(BasicIdentifier.newID(vi));
            if (virtualIssuer == null) {
                say("VI not found");
                return;
            }
        }
    }

    @Override
    public void ls(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            super.ls(inputLine);
            return;
        }
        if (getEnvironment().getKEStore() == null) {
            say("No key store enabled. You may still call \"show\" to see the signing keys for various VIs.");
            return;
        }
        super.ls(inputLine);
    }
    public static String PURGE_TIMESTAMP_FLAG = "-ts";
    public static final String PURGE_ALL_VIS = "-all";
    public static final String PURGE_LIST = "-list";

    public void purge(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("purge [" + PURGE_TIMESTAMP_FLAG + " iso | ms] [" + PURGE_LIST + " [vi] - Purge, i.e., remove old keys.  The default is to list keys that have expired.");
            say("age - get the age of the keys for the server");
            say(PURGE_TIMESTAMP_FLAG + " -an ISO 8601 timestamp or milliseconds since epoch. This also accepts \"now\" as an argument. This will be used as the cur off, so you can list expired keys before this date, or purge them.");
            say(PURGE_ALL_VIS + " - apply this to all VIs. Default is to apply it to the server keys only.");
            return;
        }
    }
}


