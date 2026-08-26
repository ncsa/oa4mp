package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.IdentifiableMap;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class KEStoreUtilities {
    private static final Logger log = LoggerFactory.getLogger(KEStoreUtilities.class);

    public static KERecord getByKID(KEStore store, String kid) {
        //return null;
        throw new NotImplementedException("Implement me!");
    }

    public static HashSet<String> getKIDs(KEStore<KERecord> store) {
        HashSet<String> kids = new HashSet<>();
        for (KERecord ker : store.values()) {
            kids.add(ker.getKid());
        }
        return kids;
    }

    public static IdentifiableMap<KERecord> getByVI(KEStore<KERecord> store, VirtualIssuer vi) {
        return getByVI(store, vi, true);
    }

    public static IdentifiableMap<KERecord> getByVI(KEStore<KERecord> store, VirtualIssuer vi, boolean validKeysOnly) {
        IdentifiableMap<KERecord> map = new IdentifiableMap<>();
        URI viURI = vi.getIdentifier().getUri();
        for (KERecord ker : store.values()) {
            if (ker.getVi().equals(viURI) && (ker.getValid() == validKeysOnly)) {
                map.put(ker.getIdentifier(), ker);
            }
        }
        return map;
    }

    public static JSONWebKeys getCurrentKeys(KEStore<KERecord> store, VirtualIssuer vi) {
        if (store.isEmpty()) {
            return new JSONWebKeys(null);
        }
        Map<Identifier, KERecord> map = getByVI(store, vi);
        if (map == null || map.isEmpty()) {
            return new JSONWebKeys(null);
        }
        return vi.getJsonWebKeys();
    }

    /**
     * Rotate the keys for the given virtual issuers, optionally removing the keys from the VI if retainInVI is true,
     * Default should be false.
     * there are any.
     *
     * @param oa2SE
     * @param vIDs
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    public static Map<Identifier, KERecord> rotate(OA2SE oa2SE,
                                                   List<Identifier> vIDs,
                                                   KEConfiguration keConfiguration,
                                                   boolean forceFlag,
                                                   boolean testOnly) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (vIDs == null || vIDs.isEmpty()) {
            DebugUtil.trace(KEStoreUtilities.class, "vIDs is null/empty. Returning... ");

            return new HashMap<>();
        }
        // If the server disallows key rotations, bail here.
        if (!keConfiguration.allowOverride && !keConfiguration.enabled) {
            DebugUtil.trace(KEStoreUtilities.class, "keConfiguration disabled. Returning... ");
            DebugUtil.trace(KEStoreUtilities.class, keConfiguration.toString());
            return new HashMap<>();
        }
        IdentifiableMap<KERecord> newRecords = new IdentifiableMap<>();
        Collection<JSONWebKey> jsonWebKeys = null;

        for (Identifier vID : vIDs) {
            VirtualIssuer vi = (VirtualIssuer) oa2SE.getVIStore().get(vID);
            if (!keConfiguration.enabled) continue;
            boolean useVI = false;
            String defaultID = null;
            IdentifiableMap<KERecord> kers;
            if (vi == null){
                 if(vID.equals(OA2SE.SERVER_VI_ID)){
                     kers = jwksToIDMap(oa2SE.getServerJWKS());
                     for(KERecord ker : kers.values()){
                         ker.setVi(OA2SE.SERVER_VI_ID.getUri());
                         ker.isValid = true;
                     }
                 }else{
                     continue; // no such VI
                 }
            } else{
                 kers = oa2SE.getKEStore().getByVI(vi);
            }
            // first case, check the store for keys.

            if (kers == null || kers.isEmpty()) {
                DebugUtil.trace(KEStoreUtilities.class, "kers is null/empty ");
                // So there are no keys in the store, just in the VI. Migrate and clean up dates.
                IdentifiableMap<KERecord> migratedRecords = new IdentifiableMap<>();

                // so no keys in the store, for this VI,
                // which *always* supersede keys in the VI.
                if (vi.hasJWKs()) {
                    jsonWebKeys = vi.getJsonWebKeys().values();
                    defaultID = vi.getDefaultKeyID();

                }else{
                    if(oa2SE.isServerVI(vi)) {
                      if(oa2SE.getServerJWKS() != null || !oa2SE.getServerJWKS().isEmpty() ){
                          jsonWebKeys = oa2SE.getServerJWKS().values();
                          defaultID= oa2SE.getServerJWKS().getDefaultKeyID();
                      }else{
                          DebugUtil.trace(KEStoreUtilities.class, "oa2SE.getServerJWKS() is null");
                          continue;
                      }
                    }
                }

                DebugUtil.trace(KEStoreUtilities.class, "getting keys from VI ");

                // rotate these and put them in the store.
                for (JSONWebKey jwk : jsonWebKeys) {
                    if (jwk.isExpired() || !jwk.isValid()) {
                        DebugUtil.trace(KEStoreUtilities.class, "invalid key, skipping");
                        continue;
                    }

                    JSONWebKey newKey = rotate(jwk, keConfiguration.cacheGracePeriod, keConfiguration.atGracePeriod);
                    KERecord keRecord = oa2SE.getKEStore().create();
                    keRecord.fromJWK(newKey, defaultID.equals(jwk.id));
                    keRecord.setValid(true);
                    keRecord.setVi(vi.getIdentifier().getUri());
                    newRecords.put(keRecord.getIdentifier(), keRecord);
                    KERecord migratedRecord = oa2SE.getKEStore().create();
                    migratedRecord.fromJWK(jwk, defaultID.equals(jwk.id));
                    migratedRecord.setValid(true);
                    migratedRecord.setVi(vi.getIdentifier().getUri());
                    migratedRecord.setNbf(new Date(System.currentTimeMillis() - 1000L)); // Backdate it by a second so it doesn't get flagged as not valid yet.
                    migratedRecords.put(migratedRecord.getIdentifier(), migratedRecord);
                }
                if (testOnly) {
                    newRecords.putAll(migratedRecords); //send back everything.
                }else{
                    oa2SE.getKEStore().putAll(newRecords); // mass update in case there are lots so store doesn't choke.
                    oa2SE.getKEStore().putAll(migratedRecords); // mass update in case there are lots so store doesn't choke.
                }
                return newRecords;
            } else {
                DebugUtil.trace(KEStoreUtilities.class, "Using KEStore Utilities to rotate " + vID);
                // have keys in store to rotate.
                return KEStoreUtilities.rotate(oa2SE.getKEStore(), kers, forceFlag, keConfiguration.cacheGracePeriod, keConfiguration.atGracePeriod, true, testOnly);
            }
        }
        DebugUtil.trace(KEStoreUtilities.class, "Default case, no keys to rotate. Returning... ");

        return new HashMap<>();
    }


    /**
     * Rotate a set of records. This sets the new keys to be valid and updates the store
     * with both new and old keys.
     *
     * <p>Note that this returns the original keys if testOnly flag is set to true
     * and in that case, no changes are done.</p>
     *
     * @param keStore
     * @param oldKERS
     * @param cacheGracePeriod
     * @param atGracePeriod
     * @return Map of the new key entry records.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static Map<Identifier, KERecord> rotate(KEStore keStore,
                                                   Map<Identifier, KERecord> oldKERS,
                                                   boolean force,
                                                   long cacheGracePeriod,
                                                   long atGracePeriod,
                                                   boolean updateOldKeys,
                                                   boolean testOnly) throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        Date now = new Date();
        if (oldKERS == null || oldKERS.isEmpty()) {
            return new HashMap<>();
        }
        Map<Identifier, KERecord> kers = new HashMap<>(oldKERS.size());
        IdentifiableMap<KERecord> updatedOLDKERs = new IdentifiableMap<>(oldKERS.size());
        if (DebugUtil.isTraceEnabled()) {
            System.err.println("rotate called with " + oldKERS.size() + " keys");
        }
        for (Identifier identifier : oldKERS.keySet()) {
            KERecord oldKER = oldKERS.get(identifier);

            /*
             * Secret debugging -- set /trace on and a bunch of stuff about the
             * key will be printed.
             */
            if (DebugUtil.isTraceEnabled()) {
                boolean x = force || (oldKER.isValid
                        && oldKER.getExp() == null
                        && (oldKER.getNbf() == null || (oldKER.getNbf().before(now))));
                String out = "\n-----\nprocessing " + oldKER.getKid() + ":" +
                        "\n     force ? " + force +
                        "\n   isValid = " + oldKER.isValid +
                        "\nexp = null ? " + (oldKER.getExp() == null) +
                        "\nnbf = null ? " + (oldKER.getNbf() == null) +
                        "\n nbf < now ? " + (oldKER.getNbf() != null && oldKER.getNbf().before(now)) +
                        "\n" + x + " = force || (valid && exp == null && (nbf == null || nbf < now))";
                System.err.println(out);
            }
            // If a key does not have a not before and is requested to rotate, do so.
            if (force || (oldKER.isValid
                    && oldKER.getExp() == null
                    && (oldKER.getNbf() == null || (oldKER.getNbf().before(now))))) {
                if (DebugUtil.isTraceEnabled()) {
                    System.err.println("passed conditional, rotating key");
                }
                KERecord newKER = rotate(keStore, oldKER, cacheGracePeriod, atGracePeriod, testOnly);
                newKER.setValid(true);
                kers.put(newKER.getIdentifier(), newKER);
                updatedOLDKERs.put(oldKER);
            } else {
                if (DebugUtil.isTraceEnabled()) {
                    System.err.println("Skipping key rotation.");
                }
            }
        }
        // now update the store
        if (updateOldKeys && !testOnly) {
            ArrayList<KERecord> updatedOLDKERsList = new ArrayList<>(updatedOLDKERs.values());
            int[] rcs = keStore.save(updatedOLDKERsList);
        }
        if (testOnly) {
            kers.putAll(updatedOLDKERs);
            return kers;
        } else {
            keStore.putAll(kers); // all new
        }
        kers.putAll(updatedOLDKERs);
        return kers;
    }

    /**
     * Rotates a key using the given grace periods. It will create a new key using the
     * old key as a guide (same algorithm, etc.).
     *
     * @param oldKey
     * @param cacheGracePeriod
     * @param atGracePeriod
     * @return
     */
    public static JSONWebKey rotate(JSONWebKey oldKey, long cacheGracePeriod, long atGracePeriod) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException {
        JWKUtil2 jwkUtil2 = new JWKUtil2();
        JSONWebKey newKey = null;
        DebugUtil.trace(KEStoreUtilities.class, "rotating key id = " + oldKey.id);

        if (cacheGracePeriod < 0L || atGracePeriod < 0L) {
            throw new IllegalArgumentException("Cache and at grace periods must be non-negative");
        }
        if (oldKey.isRSAKey()) {
            newKey = jwkUtil2.createRSAKey(oldKey.JOSEJWK.size(), oldKey.algorithm);
        }
        if (oldKey.isECKey()) {
            newKey = jwkUtil2.createECKey(oldKey.curve, oldKey.algorithm);
        }
        if (newKey == null) {
            throw new IllegalArgumentException("Unknown key type to rotate");
        }
        // newKey = rotate(oldKey, cacheGracePeriod, atGracePeriod);
        DebugUtil.trace(KEStoreUtilities.class, "   >> rotated key id = " + oldKey.id);
        setRotationDates(oldKey, newKey, cacheGracePeriod, atGracePeriod);
        return newKey;
    }

    /**
     * Rotate the Key from the Key Entry record. Note that this sets everything except the {@link KERecord#isValid} in the
     * result. Also, the new record is not saved and the expiration on the old record is updated, but also
     * not saved. This allows you to control that directly.
     *
     * @param keStore
     * @param oldKER
     * @param cacheGracePeriod
     * @param atGracePeriod
     * @return
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static KERecord rotate(KEStore<KERecord> keStore, KERecord oldKER,
                                  long cacheGracePeriod,
                                  long atGracePeriod,
                                  boolean testOnly) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        JWKUtil2 jwkUtil2 = new JWKUtil2();
        JSONWebKey newKey = null;
        JSONWebKey oldKey = oldKER.getJwk();
        if (oldKey == null) {
            throw new IllegalArgumentException("No key to rotate");
        }
        if (oldKey.isRSAKey()) {
            newKey = jwkUtil2.createRSAKey(oldKey.JOSEJWK.size(), oldKey.algorithm);
        }
        if (oldKey.isECKey()) {
            newKey = jwkUtil2.createECKey(oldKey.curve, oldKey.algorithm);
        }
        if (newKey == null) {
            throw new IllegalArgumentException("Unknown key type to rotate");
        }

        KERecord newRecord = keStore.create();
        newRecord.setVi(oldKER.getVi());
        Date now = new Date();
        Date notBefore = new Date(now.getTime() + cacheGracePeriod);
        newKey.notValidBefore = notBefore;
        newRecord.fromJWK(newKey, oldKER.getDefault());
        // If the cache grace period is zero (so immediate invalidation), remove flag for default
        // key if present. Otherwise, leave it.
        if (cacheGracePeriod == 0L && oldKER.getDefault()) {
            oldKER.setDefault(false);
            newRecord.setDefault(true);
        }
        newRecord.setIat(now);
        newRecord.setNbf(notBefore);
        oldKER.setExp(new Date(now.getTime() + cacheGracePeriod + atGracePeriod));
        newRecord.setUse(oldKER.getUse());
        return newRecord;
    }


    /**
     * Sets the dates for rotation on the keys. This means
     * <ol>
     *     <li>old key = expiration set to now + cache grace period + at grace period</li>
     *     <li>new key - issued at set to now, not valiud before is now + cache grace period</li>
     * </ol>
     *
     * @param jwk
     * @param newKey
     * @param cacheGracePeriod
     * @param atGracePeriod
     */
    public static void setRotationDates(JSONWebKey jwk, JSONWebKey newKey, long cacheGracePeriod, long atGracePeriod) {
        newKey.issuedAt = new Date();
        newKey.notValidBefore = new Date(newKey.issuedAt.getTime() + cacheGracePeriod);
        jwk.expiresAt = new Date(newKey.issuedAt.getTime() + cacheGracePeriod + atGracePeriod);
    }

    /**
     * For a virtual issuer (may be null), resolve the key configuration. This means that if the VI
     * has these configured, and the server allows for overrides, use the VI configuration. Otherwise
     * use the server configuration. Note that it is assumed you have checked if the server allows
     * key rotations separately.
     *
     * @param oa2SE
     * @param vi
     * @return
     */
    public static KEConfiguration resolveKeConfiguration(OA2SE oa2SE, VirtualIssuer vi) {
        DebugUtil.trace(KEStoreUtilities.class, "Starting resolveKeConfiguration for VI= " + vi);
        if (vi == null) {
            throw new IllegalArgumentException("Virtual issuer is null");
        }
        KEConfiguration serverKEC;
        VirtualIssuer serverVI = (VirtualIssuer) oa2SE.getVIStore().get(OA2SE.SERVER_VI_ID);
        if (serverVI == null) {
            serverKEC = oa2SE.getKeConfiguration(); // so key rotation has not been configured.
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration server vi null, using OA2SE default ");
        } else {
            if (!serverVI.hasKeyRotationConfiguration()) {
                // So they overrode the server configuration file KEC (if any) but did not configure it.
                DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration server vi has not been configuration.");
                throw new IllegalStateException("Server VI exists, but has not been configured.");
            }
            serverKEC = serverVI.getKeyRotationConfiguration();
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration using server vi for default KEC");
        }
        if (oa2SE.isServerVI(vi)) {
            if (!serverVI.hasKeyRotationConfiguration()) {
                DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration server vi has not been configuration.");
                throw new IllegalStateException("Server VI has not been configured.");
            }
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration server vi requested KEC");
            checkKEC(vi, serverKEC);
            return serverKEC;
        }

        KEConfiguration viKEC = vi.getKeyRotationConfiguration();
        if(!viKEC.allowOverride) {
            // If this allows overrides, then we can pass it along. Otherwise, it has to be checked.
            checkKEC(vi, viKEC);
        }

        if (!viKEC.allowOverride) return viKEC;

        // OK, so there is a VI with a configuration and now we have to unscramble overrides.

        if (viKEC.allowOverride) {
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration  VI found, allows overrides");
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration  setting KEC values as overrides");
            if (viKEC.atGracePeriod < 0) viKEC.atGracePeriod = serverKEC.atGracePeriod;
            if (viKEC.cacheGracePeriod < 0) viKEC.cacheGracePeriod = serverKEC.cacheGracePeriod;
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration  returned KEC=" + viKEC);
        }
        return viKEC;
    }

    private static void checkKEC(VirtualIssuer vi, KEConfiguration viKEC) {
        if (!viKEC.isConfgured()) {
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration VI has no configuration,  returning server KEC");
            throw new IllegalStateException("VI \"" + vi.getIdentifierString() + "\" has no key rotation configuration");
        }
        if (!viKEC.enabled) {
            DebugUtil.trace(KEStoreUtilities.class, "    resolveKeConfiguration VI has disabled configuration.");
            throw new IllegalStateException("VI \"" + vi.getIdentifierString() + "\" has no key rotation configuration");
        }
    }

    /**
     * Ingest a set of webkeys into the store. Default values are set if needed.
     *
     * @param keStore
     * @param jwks
     * @param vi
     * @param isValid set all keys to valid.
     * @return
     */
    public static List<String> ingest(KEStore<KERecord> keStore, JSONWebKeys jwks, VirtualIssuer vi, boolean isValid) throws NoSuchAlgorithmException, InvalidKeySpecException {
        List<String> skipped = new ArrayList<>(jwks.size());
        Map<Identifier, KERecord> kers = new HashMap<>(jwks.size());
        Set<String> allKIDs = keStore.getKIDs();
        String defaultID = vi.getDefaultKeyID();
        for (JSONWebKey jwk : jwks.values()) {
            if (allKIDs.contains(jwk.id)) {
                skipped.add(jwk.id);
                continue;
            }
            KERecord keRecord = createSingleKERecord(keStore, vi.getIdentifier().getUri(), isValid, jwk, defaultID);
            kers.put(keRecord.getIdentifier(), keRecord);
        }
        keStore.putAll(kers);
        return skipped;
    }

    /**
     * Create a single KE record from a JWK. This is not saved..
     *
     * @param keStore
     * @param viID
     * @param isValid
     * @param jwk
     * @param defaultID
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static KERecord createSingleKERecord(KEStore<KERecord> keStore,
                                                URI viID,
                                                boolean isValid,
                                                JSONWebKey jwk,
                                                String defaultID) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KERecord keRecord = keStore.create();
        keRecord.setVi(viID);
        keRecord.fromJWK(jwk, jwk.id.equals(defaultID));
        keRecord.setValid(isValid);
        if (keRecord.getIat() == null) {
            keRecord.setIat(new Date());
        }
        if (keRecord.getNbf() == null) {
            keRecord.setNbf(new Date());
        }
        return keRecord;
    }

    /**
     * Convert a set of JWKs to a map of KE records. This is a useful utility for many programs.
     * @param jwks
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static IdentifiableMap<KERecord> jwksToIDMap(JSONWebKeys jwks) throws NoSuchAlgorithmException, InvalidKeySpecException {
        IdentifiableMap map = new IdentifiableMap<>();
        if (jwks == null || jwks.isEmpty()) {
            return map;
        }
        String defaultKeyID = jwks.getDefaultKeyID();
        for (JSONWebKey jwk : jwks.values()) {
            KERecord keRecord = new KERecord(BasicIdentifier.newID(jwk.id));
            keRecord.fromJWK(jwk, defaultKeyID.equals(jwk.id));
            keRecord.setValid(true);
            map.put(keRecord.getIdentifier(), keRecord);
        }
        return map;
    }

}
