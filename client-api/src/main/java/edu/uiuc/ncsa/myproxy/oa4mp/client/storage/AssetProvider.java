package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

/**
 * Provider (i.e. a factory) for creating {@link Asset}s.
 * <p>Created by Jeff Gaynor<br>
 * on 1/29/13 at  3:45 PM
 */
public class AssetProvider<V extends Asset> implements IdentifiableProvider<V> {

    @Override
    public V get(boolean createNewIdentifier) {
        if (createNewIdentifier) {
            return (V) get(AssetStoreUtil.createID());
        }
        return (V) get((Identifier) null);
    }

    /**
     * Creates an new asset with a randomly assigned identifier.
     *
     * @return
     */
    @Override
    public V get() {
        return get(true);
    }

    /**
     * Convenience method to return the asset if the identifier is a string rather than an {@link Identifier}.
     *
     * @param identifier
     * @return
     */
    public Asset get(String identifier) {
        return get(BasicIdentifier.newID(identifier));
    }


    public Asset get(Identifier identifier) {
        return new Asset(identifier);
    }
}
