package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import org.apache.commons.codec.binary.Hex;

import java.security.SecureRandom;

/**
 * A utility that contains a couple of useful idioms.
 * <p>Created by Jeff Gaynor<br>
 * on 1/28/13 at  2:27 PM
 */
public class AssetStoreUtil {
    static SecureRandom random;

    protected static SecureRandom getRandom() {
        if (random == null) {
            random = new SecureRandom();
        }
        return random;
    }

    /**
     * Create an identifier with a random id plus timestamp.
     * @return
     */
    public static Identifier createID() {
        byte[] bytes = new byte[16];
        getRandom().nextBytes(bytes);
        return BasicIdentifier.newID("oa4mp:asset:/id/" + Hex.encodeHexString(bytes) + "/" + System.currentTimeMillis());
    }

    /**
     * Retrieves the asset with the identifier from the store.
     *
     * @param identifier
     * @param assetStore
     * @return
     */
    public static Asset get(String identifier, AssetStore assetStore) {
        return assetStore.get(BasicIdentifier.newID(identifier));
    }

    /**
     * Saves the asset with the given identifier to the store. Note that this will first check if the identifier
     * already exists in the store and replace it if it does. It will also set the id of the asset to the
     * one supplied and coarry out the save by the token.
     *
     * @param identifier
     * @param asset
     * @param assetStore
     */
    public static void save(String identifier, Asset asset, AssetStore assetStore) {
        boolean newID = false;
        newID = asset.getIdentifier() == null;
        if (!asset.getIdentifierString().equals(identifier)) {
            newID = true;
            assetStore.remove(asset.getIdentifier());
        }
        if (newID) {
            asset.setIdentifier(BasicIdentifier.newID(identifier));
        }
        if(asset.getToken() != null){
            assetStore.putByToken(asset);
        }
       assetStore.save(asset);
    }

}
