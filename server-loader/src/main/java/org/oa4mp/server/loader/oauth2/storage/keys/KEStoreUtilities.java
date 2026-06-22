package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
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

import static org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader.KEY_ROTATION_GRACE_PERIOD_DISABLED;

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
    public static IdentifiableMap<KERecord> getByVI(KEStore<KERecord> store, VirtualIssuer vi){
        IdentifiableMap<KERecord> map = new IdentifiableMap<>();
        URI viURI = vi.getIdentifier().getUri();
        for (KERecord ker : store.values()) {
            if (ker.getVi().equals(viURI)){
                map.put(ker.getIdentifier(), ker);
            }
        }
        return map;
    }

    public static JSONWebKeys getCurrentKeys(KEStore<KERecord> store, VirtualIssuer vi) {
        if(store.isEmpty()){
            return new JSONWebKeys(null);
        }
        Map<Identifier, KERecord> map = getByVI(store, vi);
        if(map == null || map.isEmpty()){
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
     * @param retainInVI
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     */
    public static void rotate(OA2SE oa2SE,
                              List<Identifier> vIDs,
                              KEConfiguration keConfiguration,
                              boolean retainInVI) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (vIDs == null || vIDs.isEmpty()) {
            return;
        }
        // If the server disallows key rotations, bail here.
        if (!keConfiguration.allowOverride && !keConfiguration.enabled) return;
        IdentifiableMap<KERecord> newRecords = new IdentifiableMap<>();
        Collection<JSONWebKey> jsonWebKeys = null;

        for (Identifier vID : vIDs) {
            VirtualIssuer vi = (VirtualIssuer) oa2SE.getVIStore().get(vID);
            if (!keConfiguration.enabled) continue;
            boolean useVI = false;
            String defaultID = null;
            if (vi == null) continue; // no such VI
            // first case, check the store for keys.
            IdentifiableMap<KERecord> kers = oa2SE.getKEStore().getByVI(vi);

            if (kers == null || kers.isEmpty()) {
                // so no keys in the store, for this VI,
                // which *always* supersede keys in the VI.
                if (!vi.hasJWKs()) continue;  // no keys anyplace.
                useVI = true;
                jsonWebKeys = vi.getJsonWebKeys().values();
                defaultID = vi.getDefaultKeyID();
                // rotate these and put them in the store.
                for (JSONWebKey jwk : jsonWebKeys) {
                    if (jwk.isExpired() || !jwk.isValid()) continue;
                    JSONWebKey newKey = rotate(jwk, keConfiguration.cacheGracePeriod, keConfiguration.atGracePeriod);
                    KERecord keRecord = oa2SE.getKEStore().create();
                    keRecord.fromJWK(newKey, defaultID.equals(newKey.id));
                    keRecord.setValid(true);
                    keRecord.setVi(vi.getIdentifier().getUri());
                    newRecords.put(keRecord.getIdentifier(), keRecord);
                }
                oa2SE.getKEStore().putAll(newRecords); // mass update in case there are lots so store doesn't choke.
            } else {
                // have keys in store to rotate.
                KEStoreUtilities.rotate(oa2SE.getKEStore(), kers, keConfiguration.cacheGracePeriod, keConfiguration.atGracePeriod, true);
            }
        }
    }


    /**
     * Rotate a set of records. This sets the new kleys to be valid and updates the store
     * with both new and old keys.
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
                                                   long cacheGracePeriod,
                                                   long atGracePeriod,
                                                   boolean updateOldKeys) throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        Date now = new Date();
        if (oldKERS == null || oldKERS.isEmpty()) {
            return new HashMap<>();
        }
        Map<Identifier, KERecord> kers = new HashMap<>(oldKERS.size());
        IdentifiableMap<KERecord> updatedOLDKERs = new IdentifiableMap<>(oldKERS.size());
        for (Identifier identifier : oldKERS.keySet()) {
            KERecord oldKER = oldKERS.get(identifier);

            // If a key does not have a not before and is requested to rotate, do so.
            //if (oldKey.isValid && (oldKey.getNbf() == null || (oldKey.getNbf().before(now) && now.before(oldKey.getExp())))) {
        if (oldKER.isValid && oldKER.getExp() == null && (oldKER.getNbf() == null || (oldKER.getNbf().before(now)))) {
            //if (oldKey.isValid) {
                KERecord newKER = rotate(keStore, oldKER, cacheGracePeriod, atGracePeriod);
                newKER.setValid(true);
                kers.put(newKER.getIdentifier(), newKER);
                updatedOLDKERs.put(oldKER);
            }
        }
        // now update the store
        if (updateOldKeys) {
            keStore.update(updatedOLDKERs); // updated expirations
        }
        keStore.putAll(kers); // all new
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
        if (oldKey.isRSAKey()) {
            newKey = jwkUtil2.createRSAKey(oldKey.JOSEJWK.size(), oldKey.algorithm);
        }
        if (oldKey.isECKey()) {
            newKey = jwkUtil2.createECKey(oldKey.curve, oldKey.algorithm);
        }
        if (newKey == null) {
            throw new IllegalArgumentException("Unknown key type to rotate");
        }
        newKey = rotate(oldKey, cacheGracePeriod, atGracePeriod);
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
    public static KERecord rotate(KEStore<KERecord> keStore, KERecord oldKER, long cacheGracePeriod, long atGracePeriod) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        JWKUtil2 jwkUtil2 = new JWKUtil2();
        JSONWebKey newKey = null;
        JSONWebKey oldKey = oldKER.getJwk();
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
        newRecord.fromJWK(newKey, oldKER.getDefault());
        Date now = new Date();
        if(oldKER.getDefault()){
            oldKER.setDefault(false);
            newRecord.setDefault(true);
        }
        newRecord.setIat(now);
        //newRecord.setNbf(new Date(now.getTime() + cacheGracePeriod));
        newRecord.setNbf(now);
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
     * has these ocnfigured, and the server allows for overrides, use the VI configuration. Otherwise
     * use the server configuration. Note that it is assumed you have checked if the server allows
     * key rotations separately.
     *
     * @param oa2SE
     * @param vi
     * @return
     */
    public static KEConfiguration resolveKeConfiguration(OA2SE oa2SE, VirtualIssuer vi) {
        if (vi == null) {
            vi = (VirtualIssuer) oa2SE.getVIStore().get(OA2SE.SERVER_VI_ID);
            if (vi == null) {
                return oa2SE.getKeConfiguration();
            }
            if (!vi.hasKeyRotationConfiguration()) {
                return oa2SE.getKeConfiguration();
            }
        }
        if (oa2SE.isServerVI(vi)) {
            if (vi.getKeyRotationConfiguration().isConfgured()) {
                return vi.getKeyRotationConfiguration();
            }
            return oa2SE.getKeConfiguration();
        }

        KEConfiguration serverKEC = oa2SE.getKeConfiguration();
        KEConfiguration outKEC = new KEConfiguration();

        if (serverKEC.allowOverride && vi != null) {
            if (!vi.isKeyRotationEnabled()) {
                outKEC.enabled = false;
                return outKEC;
            }
            outKEC.enabled = true;
            if (KEY_ROTATION_GRACE_PERIOD_DISABLED != vi.getAtGracePeriod())
                outKEC.atGracePeriod = vi.getAtGracePeriod();
            if (KEY_ROTATION_GRACE_PERIOD_DISABLED != vi.getCacheGracePeriod())
                outKEC.cacheGracePeriod = vi.getCacheGracePeriod();
        }
        return outKEC;
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

    /** Create a single KE record from a JWK. This is not saved..
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
        if(keRecord.getIat() == null){keRecord.setIat(new Date());}
        if(keRecord.getNbf() == null){keRecord.setNbf(new Date());}
        return keRecord;
    }

}
