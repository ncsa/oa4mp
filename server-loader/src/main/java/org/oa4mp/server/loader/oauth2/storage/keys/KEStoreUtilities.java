package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    public static HashSet<String> getKIDs(KEStore store) {
        throw new NotImplementedException("Implement me!");
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
                              boolean retainInVI) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (vIDs == null || vIDs.isEmpty()) {
            return;
        }
        // If the server disallows key rotations, bail here.
        KEConfiguration keConfiguration = oa2SE.getKeConfiguration();
        if (!keConfiguration.allowOverride && !keConfiguration.enabled) return;
        Map<Identifier, KERecord> newRecords = new HashMap<>();
        Collection<JSONWebKey> jsonWebKeys = null;

        for (Identifier vID : vIDs) {
            VirtualIssuer vi = (VirtualIssuer) oa2SE.getVIStore().get(vID);
            keConfiguration = resolveKeConfiguration(oa2SE, vi); // actual config for this VI
            if (!keConfiguration.enabled) continue;
            boolean useVI = false;
            String defaultID = null;
            if (vi == null) continue; // no such VI
            // first case, check the store for keys.
            Map<Identifier, KERecord> kers = oa2SE.getKEStore().getByVI(vi);

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
            }else{
                // have keys in store to rotate.
                KEStoreUtilities.rotate(oa2SE.getKEStore(), kers, keConfiguration.cacheGracePeriod, keConfiguration.atGracePeriod);
            }
        }
    }


    /**
     * Rotate a set of records. This sets the new kleys to be valid and updates the store
     * with both new and old keys.
     *
     * @param keStore
     * @param oldKeys
     * @param cacheGracePeriod
     * @param atGracePeriod
     * @return Map of the new key entry records.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static Map<Identifier, KERecord> rotate(KEStore keStore, Map<Identifier, KERecord> oldKeys, long cacheGracePeriod, long atGracePeriod) throws
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
        Date now = new Date();
        if (oldKeys == null || oldKeys.isEmpty()) {
            return new HashMap<>();
        }
        Map<Identifier, KERecord> kers = new HashMap<>(oldKeys.size());
        List<KERecord> oldKERs = new ArrayList<>(oldKeys.size());
        for (Identifier identifier : oldKeys.keySet()) {
            KERecord oldKey = oldKeys.get(identifier);

            if (oldKey.isValid && (oldKey.getNbf().before(now) && now.before(oldKey.getExp()))) {
                KERecord newKER = rotate(keStore, oldKey, cacheGracePeriod, atGracePeriod);
                newKER.setValid(true);
                kers.put(newKER.getIdentifier(), newKER);
                oldKERs.add(oldKey);
            }
        }
        // now update the store
        keStore.update(oldKeys); // updated expirations
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
        Date now = new Date();
        newKey.issuedAt = now;
        newKey.notValidBefore = new Date(newKey.issuedAt.getTime() + cacheGracePeriod);
        oldKER.setExp(new Date(newKey.issuedAt.getTime() + cacheGracePeriod + atGracePeriod));

        newRecord.fromJWK(newKey, oldKER.getDefault());

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
     * For a virtual issuer (may be null), resolve the key configuration.
     *
     * @param oa2SE
     * @param vi
     * @return
     */
    public static KEConfiguration resolveKeConfiguration(OA2SE oa2SE, VirtualIssuer vi) {
        KEConfiguration outKEC = new KEConfiguration();
        KEConfiguration serverKEC = oa2SE.getKeConfiguration();

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
}
