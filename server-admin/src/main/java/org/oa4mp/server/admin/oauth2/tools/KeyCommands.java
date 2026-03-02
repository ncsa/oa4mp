package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.admin.oauth2.base.OA4MPStoreCommands;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.keys.KERecord;
import org.oa4mp.server.loader.oauth2.storage.keys.KEStore;
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
    public KEStore getStore() {
        return getEnvironment().getKEStore();
    }

    @Override
    protected String format(Identifiable identifiable) {
        KERecord keRecord = (KERecord) identifiable;
        int width = 25; // long width, for ISO dates e.g.
        int s = 5; // short width
        String out = keRecord.getKid() +
                " "+ LJustify(keRecord.getAlg(),s) +
                " " + LJustify(keRecord.getUse(),s) +
                " " + keRecord.getValid() +
          //      " " + center((keRecord.getNbf() == null?"--": Iso8601.date2String(keRecord.getNbf())),width) +
                " " + center((keRecord.getExp()==null?"--":Iso8601.date2String(keRecord.getExp())),width) +
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
                    keRecord = (KERecord) getStore().create();
                    keRecord.setValid(true);
                    keRecord.setVi(vi.getIdentifier().getUri());// if its in the VI record, it's implicitly valid
                }
                try {
                    keRecord.fromJWK(jsonWebKey, vi.getDefaultKeyID().equals(kid));
                    if(keRecord.getVi() == null || !keRecord.getVi().equals(vi.getIdentifier().getUri())){
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
        if(0 < newKERecords.size()) {
            getStore().putAll(newKERecords); // remember that putAll will update or create as needed.
        }
        if(0 < updateKERecords.size()) {
            getStore().update(updateKERecords);
        }
        return ignoredVIRecords;
    }

    public static final String MIGRATE_LIST = "-list";
    public static final String MIGRATE_ALL_VIS = "-all";
    public static final String MIGRATE_CLEANUP = "-cleanup";

    protected void migrateHelp(InputLine line) {
        int width = 10;
        say("migrate [-list] | [-cleanup] | [-all | vi_id] migrate the keys stored in a VI to ");
        say("this store. Optionally remove them from the VI. Once migrated,");
        say("the system manages them and the keys stored in the VI are ignoared");
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

        VIStore viStore = getEnvironment().getVIStore();

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
        if (inputLine.hasArgs()) {
            foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
        }
        migrate(foundIdentifiables, cleanupMigrated);
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
                    KERecord keRecord = (KERecord) getStore().create();
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
        if(showHelp(inputLine)){
            say("set " + SET_IAT + " | " + SET_NBF + " | " + SET_EXP + " index - set the iat, nbf, or exp fields");
            say("You may set these with ISO 8601 dates or integers (as seconds since epoch)");
            return;
        }
    }
    public void get_current(InputLine inputLine) throws Throwable {
        if(showHelp(inputLine)){
            say("get_current index - get the current values for the given key");
            return;
        }
        VIStore viStore = getEnvironment().getVIStore();

        FoundIdentifiables foundIdentifiables = findByIDOrRS(viStore, inputLine.getLastArg());
        if(foundIdentifiables == null || foundIdentifiables.isEmpty()){
            say("no VIs found");
            return;
        }
        for(Identifiable identifiable : foundIdentifiables){
            VirtualIssuer vi = (VirtualIssuer) identifiable;
            say(getStore().getCurrentKeys(vi).toString());
        }

    }
}


