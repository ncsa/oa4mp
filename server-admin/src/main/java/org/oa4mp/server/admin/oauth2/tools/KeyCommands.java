package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.configuration.TimeUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.admin.oauth2.base.OA4MPStoreCommands;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.keys.KEConfiguration;
import org.oa4mp.server.loader.oauth2.storage.keys.KERecord;
import org.oa4mp.server.loader.oauth2.storage.keys.KEStore;
import org.oa4mp.server.loader.oauth2.storage.keys.KEStoreUtilities;
import org.oa4mp.server.loader.oauth2.storage.vi.VIStore;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;

import java.util.*;

import static edu.uiuc.ncsa.security.core.util.StringUtils.*;

public class KeyCommands extends OA4MPStoreCommands {
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
        String out = keRecord.getKid() +
                " " + LJustify(keRecord.getAlg(), s) +
                " " + LJustify(keRecord.getUse(), s) +
                " " + keRecord.getValid() +
                //      " " + center((keRecord.getNbf() == null?"--": Iso8601.date2String(keRecord.getNbf())),width) +
                " " + center((keRecord.getExp() == null ? "--" : Iso8601.date2String(keRecord.getExp())), width) +
                " " + keRecord.getVi() +
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
                    keRecord =  getStore().create();
                    keRecord.setValid(true);
                    keRecord.setVi(vi.getIdentifier().getUri());// if its in the VI record, it's implicitly valid
                }
                try {
                    keRecord.fromJWK(jsonWebKey, vi.getDefaultKeyID().equals(kid));
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
        say("migrate ["+MIGRATE_LIST + "] | ["+ MIGRATE_CLEANUP + "] | [" +
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
        boolean listMigrated = inputLine.hasArg(MIGRATE_LIST);
        boolean migrateAll = inputLine.hasArg(MIGRATE_ALL_VIS);
        boolean cleanupMigrated = inputLine.hasArg(MIGRATE_CLEANUP);
        inputLine.removeSwitch(MIGRATE_LIST);
        inputLine.removeSwitch(MIGRATE_ALL_VIS);
        inputLine.removeSwitch(MIGRATE_CLEANUP);
        boolean migrateServerKeys = inputLine.hasArg(MIGRATE_SERVER_KEYS);

        VIStore<VirtualIssuer> viStore = getEnvironment().getVIStore();

        if(migrateServerKeys){
          VirtualIssuer vi =  viStore.get(OA2SE.SERVER_VI_ID);
          // if it does note xist, create it.
            if(vi == null){
                vi = viStore.create();
                vi.setIdentifier(OA2SE.SERVER_VI_ID);
                vi.setValid(true);
                vi.setDescription("Dafault OA4MP Server Configuration");
                viStore.save(vi);
            }
            // If there are keys in the VI, migrate them.
            if(vi.hasJWKs()){

            }

            // No keys in the VI, check OA2SE 9service environment) in case they are in the XML configuration.

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
                say(vi.getIdentifierString());
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
                    KERecord keRecord =  getStore().create();
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
            say("get_current index - get the current values for the given key");
            return;
        }
        VIStore viStore = getEnvironment().getVIStore();

        FoundIdentifiables foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
        if (foundIdentifiables == null || foundIdentifiables.isEmpty()) {
            say("no VIs found");
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
        say(KR_ALL + " = rotate all keys");
        say(KR_KID + " = rotate the specific key by is key id");
        say(KR_VI + " = rotate the keys by for a given virtual issuer");
        say("Otherwise, the index is the index (unique identifier or element in a result set) of the key in the store.");
        say("This will rotate the key(s) either per VI's policy or you may directly set the lifetimes");
        say("Setting at least one of " + KR_CACHE_LIFETIME + " or " + KR_AT_LIFETIME + " will override the policy");
        say("These accept lifetime in seconds (default) or with units, e.g. " + KR_AT_LIFETIME + " \"25 min\" (note the quotes!)");
        say();
        say("E.g. Totate all the keys in the store, using specific cachse lifetime.");
        sayi("  rotate " + KR_ALL + " " + KR_CACHE_LIFETIME + " \"2 days\"");
        say("E.g. Rotate the keys for a given VI.");
        sayi("  rotate " + KR_VI + " oa4mp:/vi/1234567890");
        say("Note that htis uses the policies of the VI and server.");;
    }

    public void rotate(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            rotateHelp(inputLine);
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

        boolean doVI = inputLine.hasArg(KR_VI);
        if(doVI){
            viID = BasicIdentifier.newID(inputLine.getNextArgFor(KR_VI));
            inputLine.removeSwitchAndValue(KR_VI);
            // try finding VIs
            VIStore viStore = getEnvironment().getVIStore();
            FoundIdentifiables foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
            if (foundIdentifiables == null || foundIdentifiables.isEmpty()) {
                say("no Key entries or VIs found");
                return;
            }
            KEStoreUtilities.rotate(getEnvironment(), foundIdentifiables.getIdentifiers(), false);
            return;
        }
        boolean doKID = inputLine.hasArg(KR_KID);
        if (doKID) {
            String kid = inputLine.getNextArgFor(KR_KID);
            inputLine.removeSwitchAndValue(KR_KID);
            KERecord keRecord = getEnvironment().getKEStore().getByKID(kid);
            if (keRecord== null) {
                say("key with kid " + kid + " not found");
            }else{
                // get the policy.
                VirtualIssuer vi = (VirtualIssuer) getEnvironment().getVIStore().get(keRecord.getVi());
                if (!overrideKEC) {
                    KEConfiguration keConfiguration = KEStoreUtilities.resolveKeConfiguration(getEnvironment(), vi);
                    if (!keConfiguration.enabled) {
                        return;
                    }
                    if (cacheLifetime != null) cacheLifetime = keConfiguration.cacheGracePeriod;
                    if (atLifetime != null) atLifetime = keConfiguration.atGracePeriod;
                }
                KERecord newRecord = KEStoreUtilities.rotate(getEnvironment().getKEStore(), keRecord, cacheLifetime, atLifetime);
                newRecord.setValid(true);
                getEnvironment().getKEStore().update(keRecord);
                getEnvironment().getKEStore().save(newRecord);
                say("rotated key, kid= " + newRecord.getKid());
            }
            return;
        }
        boolean doAll = inputLine.hasArg(KR_ALL);
        inputLine.removeSwitch(KR_ALL);
        if(doAll){
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
            Map<Identifier, KERecord> newRecords = KEStoreUtilities.rotate(getStore(), keRecords, cacheLifetime, atLifetime);
            say("rotated " + newRecords.size() + " keys");
            return;
        }

    }

}


